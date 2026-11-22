"""Versioned triage signals based solely on recorded TCP connection state."""

from typing import Literal, get_args


Protocol = Literal["tcp", "udp", "icmp", "unknown_transport"]
PROTOCOLS = get_args(Protocol)
STATE_PATTERN = r"^[A-Z0-9_]{1,24}$"

RULES_BY_STATE = {
    "S0": "tcp-no-response-v1",
    "REJ": "tcp-rejected-v1",
}

FINDING_EXPLANATIONS = {
    "tcp-no-response-v1": "Zeek recorded an attempted TCP connection with no observed reply.",
    "tcp-rejected-v1": "Zeek recorded a rejected TCP connection attempt.",
}


def rule_for_flow(protocol, state):
    """A finding is an observation for review and carries no attack label."""
    return RULES_BY_STATE.get(state) if protocol == "tcp" else None
