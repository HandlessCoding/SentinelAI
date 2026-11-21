"""Deterministic preparation of six common flow fields for Level 2.

The UQ adapter preserves nProbe's source-to-destination orientation. A future
adapter needs equivalent byte accounting, direction, duration, and flow
boundaries before its records can use this schema. No values are fitted.
"""

import re
from collections.abc import Mapping
from typing import NamedTuple

SCHEMA_VERSION = "flow-core-v1"
MAX_PROTOCOL = (1 << 8) - 1
MAX_FLOW_VALUE = (1 << 64) - 1
SOURCE_COLUMNS = (
    "PROTOCOL",
    "FLOW_DURATION_MILLISECONDS",
    "IN_PKTS",
    "OUT_PKTS",
    "IN_BYTES",
    "OUT_BYTES",
)
_LIMITS = (MAX_PROTOCOL,) + (MAX_FLOW_VALUE,) * 5
_INTEGER_TEXT = re.compile(r"([0-9]+)(?:\.0+)?")


class FlowValidationError(ValueError):
    """Expose the rejected field and reason without including its value."""

    def __init__(self, column: str, reason: str) -> None:
        self.column = column
        self.reason = reason
        super().__init__(f"{column}: {reason}")


class FlowFeatures(NamedTuple):
    """Ordered, normalized values with the exporter-defined flow direction."""

    protocol: int
    duration_ms: int
    src_to_dst_packets: int
    dst_to_src_packets: int
    src_to_dst_octets: int
    dst_to_src_octets: int

    def as_tuple(self) -> tuple[int, int, int, int, int, int]:
        """Return a hashable exact key in canonical schema order."""
        return tuple(self)

    def as_dict(self) -> dict[str, int]:
        """Return the named features for downstream preprocessing."""
        return self._asdict()


CANONICAL_COLUMNS = FlowFeatures._fields


def _parse_uint(value: object, column: str, limit: int) -> int:
    if value is None:
        raise FlowValidationError(column, "missing")
    if isinstance(value, str):
        token = value.strip(" \t\r\n")
        if not token:
            raise FlowValidationError(column, "missing")
        match = _INTEGER_TEXT.fullmatch(token)
        if match is None:
            raise FlowValidationError(column, "invalid_integer")
        digits = match[1].lstrip("0") or "0"
        if len(digits) > 20:
            raise FlowValidationError(column, "out_of_range")
        value = int(digits)
    if type(value) is not int:
        raise FlowValidationError(column, "invalid_integer")
    if not 0 <= value <= limit:
        raise FlowValidationError(column, "out_of_range")
    return value


def normalize_flow(record: Mapping[str, object]) -> FlowFeatures:
    """Validate a UQ NetFlow record and select just the common flow fields.

    Integers and exact ASCII integer text are accepted. A zero-only decimal
    suffix is allowed for CSV exports with lossless forms such as "24.0".
    Measured zeros are retained, and absent counters are never imputed.
    Source metadata and labels cannot enter the returned predictors.
    """
    if not isinstance(record, Mapping):
        raise FlowValidationError("record", "invalid_mapping")
    return FlowFeatures(*(
        _parse_uint(record.get(column), column, limit)
        for column, limit in zip(SOURCE_COLUMNS, _LIMITS, strict=True)
    ))
