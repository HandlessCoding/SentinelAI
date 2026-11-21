"""Fixed and experimentally comparable flow projections for Level 2."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from operator import itemgetter
from struct import Struct

from ml.level2_flow_schema import (
    CANONICAL_COLUMNS,
    MAX_FLOW_VALUE,
    MAX_PROTOCOL,
    SOURCE_COLUMNS,
    FlowValidationError,
    _parse_uint,
)


TCP = 6
UDP = 17
_TRANSPORT_PORTS = frozenset((TCP, UDP))
_TCP_ONLY = frozenset((TCP,))
_U16_MAX = (1 << 16) - 1

FeatureVector = tuple[int | None, ...]
FeatureResult = FeatureVector | FlowValidationError


@dataclass(frozen=True)
class FeatureColumn:
    """A single explicitly allowed exporter field and its canonical name."""

    source: str
    name: str
    maximum: int = MAX_FLOW_VALUE
    protocols: frozenset[int] | None = None

    @property
    def struct_code(self) -> str:
        if self.maximum <= MAX_PROTOCOL:
            return "B"
        if self.maximum <= _U16_MAX:
            return "H"
        return "Q"


@dataclass(frozen=True)
class FeatureSet:
    """Ordered, named projection with an exact binary key representation."""

    name: str
    features: tuple[FeatureColumn, ...]
    _packing: Struct = field(init=False, repr=False, compare=False)
    _nullable: tuple[int, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        nullable = tuple(
            index for index, feature in enumerate(self.features)
            if feature.protocols is not None
        )
        codes = "".join(feature.struct_code for feature in self.features)
        prefix = "H" if nullable else ""
        object.__setattr__(self, "_nullable", nullable)
        object.__setattr__(self, "_packing", Struct(f">{prefix}{codes}"))

    @property
    def source_columns(self) -> tuple[str, ...]:
        return tuple(feature.source for feature in self.features)

    @property
    def columns(self) -> tuple[str, ...]:
        return tuple(feature.name for feature in self.features)

    @property
    def key_bytes(self) -> int:
        return self._packing.size

    def select(self, record: Mapping[str, object]) -> FeatureVector:
        """Select one vector or raise the first applicable field error."""
        values = FeatureSelector((self.name,)).prepare(record)[self.name]
        if isinstance(values, FlowValidationError):
            raise values
        return values

    def pack(self, values: FeatureVector) -> bytes:
        """Encode a selected vector without conflating structural nulls and zeros."""
        if not self._nullable:
            return self._packing.pack(*values)
        presence_bits = sum(
            (1 << bit) for bit, index in enumerate(self._nullable)
            if values[index] is None
        )
        if not presence_bits:
            return self._packing.pack(0, *values)
        return self._packing.pack(
            presence_bits, *(0 if value is None else value for value in values)
        )


_CORE = tuple(
    FeatureColumn(source, name, MAX_PROTOCOL if source == "PROTOCOL" else MAX_FLOW_VALUE)
    for source, name in zip(SOURCE_COLUMNS, CANONICAL_COLUMNS, strict=True)
)
_PORTS = (
    FeatureColumn("L4_SRC_PORT", "src_port", _U16_MAX, _TRANSPORT_PORTS),
    FeatureColumn("L4_DST_PORT", "dst_port", _U16_MAX, _TRANSPORT_PORTS),
)
_FLAGS = (
    FeatureColumn("TCP_FLAGS", "tcp_flags", _U16_MAX, _TCP_ONLY),
    FeatureColumn("CLIENT_TCP_FLAGS", "client_tcp_flags", _U16_MAX, _TCP_ONLY),
    FeatureColumn("SERVER_TCP_FLAGS", "server_tcp_flags", _U16_MAX, _TCP_ONLY),
)
_LENGTHS = (
    FeatureColumn("MIN_IP_PKT_LEN", "min_ip_packet_octets"),
    FeatureColumn("MAX_IP_PKT_LEN", "max_ip_packet_octets"),
)
_TTL = (
    FeatureColumn("MIN_TTL", "min_ttl", MAX_PROTOCOL),
    FeatureColumn("MAX_TTL", "max_ttl", MAX_PROTOCOL),
)
_RETRANSMISSIONS = (
    FeatureColumn("RETRANSMITTED_IN_PKTS", "src_to_dst_retransmitted_packets", protocols=_TCP_ONLY),
    FeatureColumn("RETRANSMITTED_OUT_PKTS", "dst_to_src_retransmitted_packets", protocols=_TCP_ONLY),
    FeatureColumn("RETRANSMITTED_IN_BYTES", "src_to_dst_retransmitted_octets", protocols=_TCP_ONLY),
    FeatureColumn("RETRANSMITTED_OUT_BYTES", "dst_to_src_retransmitted_octets", protocols=_TCP_ONLY),
)

FEATURE_SETS = {
    name: FeatureSet(name, (*_CORE, *extras))
    for name, extras in (
        ("core", ()),
        ("core_ports", _PORTS),
        ("core_tcp_flags", _FLAGS),
        ("core_packet_lengths", _LENGTHS),
        ("core_ttl", _TTL),
        ("core_retransmissions", _RETRANSMISSIONS),
        ("core_lengths_flags", (*_LENGTHS, *_FLAGS)),
        ("core_all", (*_PORTS, *_FLAGS, *_LENGTHS, *_TTL, *_RETRANSMISSIONS)),
    )
}

_RANGE_PAIRS = (
    ("MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN"),
    ("MIN_TTL", "MAX_TTL"),
)


def _parse_field(value: object, source: str, maximum: int) -> int:
    """Fast path for ordinary CSV spellings with the G14 parser as fallback."""
    if type(value) is str:
        if value == "0":
            return 0
        if len(value) <= 20 and value.isascii() and value.isdecimal():
            number = int(value)
            if number <= maximum:
                return number
            raise FlowValidationError(source, "out_of_range")
    return _parse_uint(value, source, maximum)


class FeatureSelector:
    """Validate shared fields once per row and return each candidate's result."""

    def __init__(self, names: Sequence[str] = tuple(FEATURE_SETS)) -> None:
        if not names or len(names) != len(set(names)):
            raise ValueError("Choose one or more distinct feature set names")
        try:
            self.sets = tuple(FEATURE_SETS[name] for name in names)
        except KeyError as error:
            raise ValueError(f"Unknown feature set: {error.args[0]}") from None
        self.features = tuple(dict.fromkeys(
            feature for spec in self.sets for feature in spec.features
        ))
        self.source_columns = tuple(feature.source for feature in self.features)
        positions = {source: index for index, source in enumerate(self.source_columns)}
        self._projections = tuple(
            (spec.name, itemgetter(*(positions[source] for source in spec.source_columns)))
            for spec in self.sets
        )
        self._pairs = tuple(
            (positions[low], positions[high], high)
            for low, high in _RANGE_PAIRS if low in positions and high in positions
        )

    def prepare(self, record: Mapping[str, object]) -> dict[str, FeatureResult]:
        """Return candidate vectors or safe validation errors by candidate name."""
        if not isinstance(record, Mapping):
            raise FlowValidationError("record", "invalid_mapping")
        return self.prepare_values(tuple(record.get(source) for source in self.source_columns))

    def bind(self, header: Sequence[str]) -> "BoundFeatureSelector":
        """Bind a CSV header once so rows need no per-record field mappings."""
        return BoundFeatureSelector(self, header)

    def prepare_values(self, values: Sequence[object]) -> dict[str, FeatureResult]:
        """Prepare values in `source_columns` order without inspecting other fields."""
        if len(values) != len(self.features):
            raise FlowValidationError("record", "invalid_width")
        try:
            protocol = _parse_field(values[0], "PROTOCOL", MAX_PROTOCOL)
        except FlowValidationError as error:
            return dict.fromkeys((spec.name for spec in self.sets), error)

        parsed: list[int | None | FlowValidationError] = [protocol]
        has_errors = False
        for feature, value in zip(self.features[1:], values[1:], strict=True):
            if feature.protocols is not None and protocol not in feature.protocols:
                parsed.append(None)
            else:
                try:
                    parsed.append(_parse_field(value, feature.source, feature.maximum))
                except FlowValidationError as error:
                    parsed.append(error)
                    has_errors = True

        for low_index, high_index, high in self._pairs:
            low_value, high_value = parsed[low_index], parsed[high_index]
            if isinstance(low_value, int) and isinstance(high_value, int) and low_value > high_value:
                parsed[high_index] = FlowValidationError(high, "below_reported_minimum")
                has_errors = True

        if not has_errors:
            return {name: project(parsed) for name, project in self._projections}

        results: dict[str, FeatureResult] = {}
        for name, project in self._projections:
            candidate = project(parsed)
            results[name] = next(
                (value for value in candidate if isinstance(value, FlowValidationError)),
                candidate,
            )
        return results


class BoundFeatureSelector:
    """Feature selection for width-checked rows in one existing CSV layout."""

    def __init__(self, selector: FeatureSelector, header: Sequence[str]) -> None:
        positions = {name: index for index, name in enumerate(header)}
        if len(positions) != len(header):
            raise ValueError("Feature selection requires unique CSV column names")
        missing = set(selector.source_columns).difference(positions)
        if missing:
            raise ValueError(f"CSV lacks required feature columns: {', '.join(sorted(missing))}")
        self.selector = selector
        self.width = len(header)
        self.get_values = itemgetter(*(positions[column] for column in selector.source_columns))

    def prepare(self, row: Sequence[object]) -> dict[str, FeatureResult]:
        if len(row) != self.width:
            raise FlowValidationError("record", "invalid_width")
        return self.selector.prepare_values(self.get_values(row))
