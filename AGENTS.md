# SentinelAI engineering instructions

## Project context

- Read [GLOSSARY.md](GLOSSARY.md) and relevant [architecture decisions](docs/adr/) before working on the domain. Use the glossary's terms and surface conflicts with existing decisions.
- Use the [documentation index](docs/README.md) to find setup and operational guides. Read the [architecture](docs/ARCHITECTURE.md) for system boundaries, the [roadmap](docs/ROADMAP.md) for milestone status, and the [research archive](docs/research/README.md) for evidence and limitations. Use the [lab guide](docs/LAB_GUIDE.md) for authorized lab procedures.

## Engineering and testing

- Inspect the code, tests, and docs before proposing changes. Favor correctness, maintainability, security, and performance. Reuse existing components and introduce abstractions when current needs justify them.
- For significant designs, explain requirements, alternatives, tradeoffs, risks, and acceptance criteria. Challenge assumptions and distinguish observed behavior, agreed plans, and open decisions.
- Preserve supported behavior and data compatibility. Consider invalid input, partial failures, retries, and concurrency where they affect correctness.
- Add focused automated tests for new behavior and regressions. Run relevant tests, type checks, builds, and security checks. Report what ran, the results, and any skipped or unverified behavior.

## Major milestone workflow

Use the installed skills for the applicable stages of major milestones. Get explicit approval before advancing to the next major stage. Keep routine changes proportionate. Use this file, the glossary, approved ADRs, architecture docs, and relevant research as inputs throughout.

1. **Grill With Docs.** Use `grill-with-docs`, `grilling`, and `domain-modeling` to challenge requirements and compare alternatives one important decision at a time. Record agreed decisions in the relevant ADR. Update the glossary when terminology needs clarification.
2. **To Spec.** Use `to-spec` to describe scope, interfaces, risks, acceptance criteria, and required tests. Use `setup-matt-pocock-skills` to configure the issue tracker before publishing specs or tickets if the tracker setup is pending.
3. **To Tickets.** Use `to-tickets` to split the approved spec into small, independently verifiable tasks with explicit dependencies.
4. **Implement with TDD.** Use `implement` and `tdd` for approved tickets. Add focused automated tests and verify the results against the spec.
5. **Code Review.** Use `code-review` to independently check the implementation against repository standards and the approved spec, including architecture, security, performance, and compatibility.
6. **Pull Request.** When authorized, present verified changes, test results, and remaining limitations for review. Obtain explicit approval before merging.

## Security and data handling

- Keep monitoring and capture within the authorized scope. For lab work, verify isolation before collecting traffic and stop if isolation fails. Get explicit approval before connecting to any real external network, widening the monitoring scope, making significant infrastructure changes, or performing destructive operations.
- Treat external inputs as untrusted. Keep credentials, raw captures, private telemetry, local authorization records, restricted datasets, and model binaries outside Git. Share approved summaries and retain sensitive evidence in authorized storage.

## ML evaluation

- Track dataset, capture, labeling, feature, model, and evaluation provenance. Check feature semantics and extraction parity before applying a model to another source. Keep unresolved labels `unknown` and account for them separately.
- Keep related captures and device or session groups together when splitting data. Audit overlap and leakage. Fit on the training partition, select models and thresholds on designated development partitions, and freeze the pipeline and operating point before held-out evaluation.
- Report class and group support, false-positive rates, and uncertainty or evidence limits. Qualify deployment claims with representative independent evidence. Distinguish benchmark results, supervised lab results, and operational evidence.

## Git and documentation

- Use dedicated branches for substantial changes and keep commits focused. Preserve unrelated work. Get explicit authorization before force-pushing, rewriting history, or merging into the default branch.
- Keep docs concise and link to existing evidence. Update the glossary when a term is agreed. Record an ADR when an agreed, consequential decision has evidence and a meaningful tradeoff. Label planned work as planned and support readiness claims with verification.
