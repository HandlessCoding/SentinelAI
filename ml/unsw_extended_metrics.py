"""Fit disjoint probability maps and thresholds, then assess the frozen decisions."""

from collections import Counter
from time import perf_counter, process_time
import warnings

import numpy as np
from scipy.special import logit
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss, roc_auc_score, roc_curve

from ml.run_baseline import binary_metrics, class_distribution
from ml.run_unsw_development import peak_rss_bytes
from ml.unsw_extended_design import FEATURE_SETS, positions
from ml.unsw_overnight_models import METRICS, make_pipeline, spread


METHODS = ("raw", "sigmoid", "isotonic")
TARGETS = {"r95": 0.95, "r965": 0.965, "r99": 0.99}
DEFAULT_POLICY = "raw-default"
DIAGNOSTIC_POLICY = "raw-r965"
POLICIES = (DEFAULT_POLICY, *(f"{method}-{target}" for method in METHODS for target in TARGETS))
EVALUATION_FLOOR = 0.95
DIAGNOSTIC_SEED = 32243


def fit_probability_map(method, scores, labels):
    if method == "raw":
        return lambda values: values
    if method == "isotonic":
        calibration = IsotonicRegression(out_of_bounds="clip").fit(scores, labels)
        return calibration.predict
    if method != "sigmoid":
        raise ValueError("Unknown probability calibration method")

    def log_odds(values):
        return logit(np.clip(values, 1e-7, 1 - 1e-7)).reshape(-1, 1)

    calibration = LogisticRegression(C=10, solver="lbfgs", max_iter=500).fit(log_odds(scores), labels)
    return lambda values: calibration.predict_proba(log_odds(values))[:, 1]


def calibration_threshold(labels, scores, floor):
    fpr, recall, thresholds = roc_curve(labels, scores, drop_intermediate=False)
    eligible = np.flatnonzero(np.isfinite(thresholds) & (recall >= floor))
    if not len(eligible):
        raise ValueError("No finite calibration threshold satisfied its recall constraint")
    chosen = min(eligible, key=lambda i: (fpr[i], -recall[i], -thresholds[i]))
    return float(thresholds[chosen])


def decisions(probability_scores, probability_labels, threshold_scores, threshold_labels, policies):
    """Accept only the two designated calibration roles. Evaluation input is absent."""
    methods = sorted({policy.split("-")[0] for policy in policies})
    maps = {method: fit_probability_map(method, probability_scores, probability_labels) for method in methods}
    mapped = {method: transform(threshold_scores) for method, transform in maps.items()}
    result = {}
    for policy in policies:
        method, target = policy.split("-")
        threshold = 0.5 if policy == DEFAULT_POLICY else calibration_threshold(threshold_labels, mapped[method], TARGETS[target])
        result[policy] = {"method": method, "target": TARGETS.get(target), "threshold": threshold,
                          "threshold_confusion": confusion(threshold_labels, classify(mapped[method], policy, threshold))}
    return maps, result


def classify(scores, policy, threshold):
    return scores > threshold if policy == DEFAULT_POLICY else scores >= threshold


def confusion(labels, predicted):
    normal, attack = labels == 0, labels == 1
    fp, tp = int(np.count_nonzero(normal & predicted)), int(np.count_nonzero(attack & predicted))
    return [[int(normal.sum()) - fp, fp], [int(attack.sum()) - tp, tp]]


def error_slices(data, indices, labels, predicted):
    fields = {name: data.predictors[indices, data.columns.index(name)] for name in ("proto", "service", "sttl")}
    ttl = fields.pop("sttl").astype(float)
    fields["source_ttl_range"] = np.asarray(["<32", "32–63", "64–127", "128–254", "255+"])[
        np.digitize(ttl, [32, 64, 128, 255])
    ]
    result = {}
    for name, values in fields.items():
        frequent = sorted(Counter(values).items(), key=lambda item: (-item[1], item[0]))[:7]
        included = [value for value, _ in frequent]
        buckets = {str(value): values == value for value in included}
        if len(values) > sum(count for _, count in frequent):
            buckets["other"] = ~np.isin(values, included)
        result[name] = {value: confusion(labels[match], predicted[match]) for value, match in buckets.items()}
    return result


def fit_rotation(config, data, roles, seed, fold, guard, *, policies=POLICIES, diagnostics=False, freeze=None):
    started, cpu = perf_counter(), process_time()
    columns = list(FEATURE_SETS[config["feature_set"]])
    inputs = data.predictors[:, positions(data.columns, columns)]
    labels = data.labels
    params = {**config["parameters"], "random_state": seed}
    if isinstance(params.get("class_weight"), dict):
        params["class_weight"] = {int(label): weight for label, weight in params["class_weight"].items()}
    model = make_pipeline({**config, "parameters": params}, columns)
    fitting, probability, threshold, evaluation = (roles[name] for name in ("fit", "probability", "threshold", "evaluation"))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        model.fit(inputs[fitting], labels[fitting])
        fit_seconds = perf_counter() - started
        guard()
        probability_scores = model.predict_proba(inputs[probability])[:, 1]
        threshold_scores = model.predict_proba(inputs[threshold])[:, 1]
        maps, locked = decisions(probability_scores, labels[probability], threshold_scores, labels[threshold], policies)
        guard()
        if freeze is not None:
            freeze(locked)
        raw_scores = model.predict_proba(inputs[evaluation])[:, 1]
        expected = labels[evaluation]
        scores = {method: transform(raw_scores) for method, transform in maps.items()}
        metrics = {policy: {**decision, "metrics": binary_metrics(expected, classify(
            scores[decision["method"]], policy, decision["threshold"]
        ))} for policy, decision in locked.items()}
        probability_quality = {method: {"brier": float(brier_score_loss(expected, values)),
                                        "log_loss": float(log_loss(expected, values, labels=[0, 1]))}
                               for method, values in scores.items()}
        diagnostic_policy = DIAGNOSTIC_POLICY if DIAGNOSTIC_POLICY in policies else policies[0]
        decision = locked[diagnostic_policy]
        errors = error_slices(data, evaluation, expected, classify(scores[decision["method"]], diagnostic_policy,
                                                                    decision["threshold"]))
        score_diagnostics = {"evaluation_raw_auc": float(roc_auc_score(expected, raw_scores))}
        if diagnostics:
            sample = np.random.default_rng(DIAGNOSTIC_SEED + fold).choice(fitting, min(2_048, len(fitting)), replace=False)
            if len(np.unique(labels[sample])) == 2:
                score_diagnostics["fitting_sample_raw_auc"] = float(roc_auc_score(labels[sample], model.predict_proba(inputs[sample])[:, 1]))
    return {"seed": seed, "fold": fold, "policies": metrics, "probability_quality": probability_quality,
            "diagnostic_policy": diagnostic_policy, "errors_by_field": errors, "score_diagnostics": score_diagnostics,
            "class_counts": {role: class_distribution(labels[indices]) for role, indices in roles.items()},
            "fit_seconds": fit_seconds, "wall_seconds": perf_counter() - started, "cpu_seconds": process_time() - cpu,
            "peak_process_rss_bytes_so_far": peak_rss_bytes(),
            "warnings": sorted({f"{item.category.__name__}: {item.message}" for item in caught})}


def aggregate_policies(rows):
    return {policy: {metric: spread([row["policies"][policy]["metrics"][metric] for row in rows])
                     for metric in METRICS} for policy in rows[0]["policies"]}


def rank_metrics(metrics):
    recall = metrics["recall"]["min"]
    fpr = metrics["false_positive_rate"]
    if recall >= EVALUATION_FLOOR:
        return 0, fpr["mean"], fpr["max"], -recall
    return 1, -recall, fpr["mean"], fpr["max"]


def best_policy(aggregate):
    """Prefer raw probabilities on identical classification outcomes."""
    return min((policy for policy in aggregate if policy != DEFAULT_POLICY),
               key=lambda policy: (*rank_metrics(aggregate[policy]), METHODS.index(policy.split("-")[0]), policy))
