"""Data minimization.

Takes a raw set of records and a requested set of fields, consults the
policy engine, and returns only what the policy allows:

  * ALLOW fields          -> raw values pass through.
  * AGGREGATE_ONLY fields -> only sum/avg/min/max/count are computed;
                             the individual values never leave this
                             function.
  * DENY fields           -> dropped entirely, and logged.

This is the "the LLM never needed to see the names or emails" step
from the project README (section 9).
"""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from typing import Any

from .audit import AuditLog
from .decision import Decision
from .policy_engine import PolicyEngine


class PolicyViolation(Exception):
    """Raised when a caller demands raw access to a non-ALLOW field."""


@dataclass
class MinimizedResult:
    agent: str
    allowed_fields: dict[str, list[Any]] = dataclass_field(default_factory=dict)
    aggregates: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    denied_fields: list[str] = dataclass_field(default_factory=list)

    def is_denied(self, field_name: str) -> bool:
        return field_name in self.denied_fields


def _record_key(field_name: str) -> str:
    """Map a dotted policy field name (e.g. 'employee.salary') to the
    key actually used in a record dict (e.g. 'salary'). Falls back to
    the full name if there's no dot, so flat schemas work too."""
    return field_name.rsplit(".", 1)[-1]


# k-anonymity floor for scalar release. Below this group size, `avg` and
# `sum` disclose (and at count == 1 exactly equal) an individual raw
# value, so they are suppressed. Sized for the demo scenarios, which
# aggregate over >= 3 records (audit finding I-1).
_MIN_GROUP_SIZE = 3


def _aggregate(
    values: list[float], min_group: int = _MIN_GROUP_SIZE
) -> dict[str, float | None | str]:
    # min / max are deliberately NOT returned: they are individual,
    # attributable point values (the exact salary of one real person),
    # not aggregates (audit finding H-1).
    n = len(values)
    if n < min_group:
        # Group too small to release a scalar without identifying a
        # raw value. Expose only the count (audit finding I-1).
        return {
            "count": n,
            "sum": None,
            "avg": None,
            "suppressed": f"group < k={min_group}",
        }
    return {
        "count": n,
        "sum": sum(values),
        "avg": round(sum(values) / n, 2),
    }


class DataMinimizer:
    """Applies a PolicyEngine's decisions to a concrete dataset."""

    def __init__(self, policy_engine: PolicyEngine, audit_log: AuditLog | None = None) -> None:
        self.policy_engine = policy_engine
        self.audit_log = audit_log or AuditLog()

    def minimize(
        self,
        agent: str,
        records: list[dict[str, Any]],
        requested_fields: list[str],
    ) -> MinimizedResult:
        result = MinimizedResult(agent=agent)
        decisions = self.policy_engine.evaluate_request(agent, requested_fields)

        for fd in decisions:
            self.audit_log.record(fd.agent, fd.field, fd.decision, fd.reason)

            if fd.decision is Decision.DENY:
                result.denied_fields.append(fd.field)
                continue

            key = _record_key(fd.field)
            # Positional alignment: one entry per record, `None` where the
            # key is absent, so an ALLOW column stays row-aligned with the
            # dataset even over a sparse / non-uniform schema (audit M-1).
            values = [record.get(key) for record in records]

            if fd.decision is Decision.ALLOW:
                result.allowed_fields[fd.field] = values
            elif fd.decision is Decision.AGGREGATE_ONLY:
                numeric_values = [v for v in values if isinstance(v, (int, float))]
                result.aggregates[fd.field] = _aggregate(numeric_values)

        return result

    def require_raw(self, agent: str, field_name: str) -> Decision:
        """Explicit guard for code paths that need a hard yes/no.

        Raises PolicyViolation instead of silently degrading, for
        callers that would otherwise misuse an AGGREGATE_ONLY or
        DENY field as if it were raw data.
        """
        fd = self.policy_engine.evaluate_field(agent, field_name)
        self.audit_log.record(fd.agent, fd.field, fd.decision, fd.reason)
        if fd.decision is not Decision.ALLOW:
            raise PolicyViolation(
                f"Agent '{agent}' requested raw access to '{field_name}' "
                f"but policy says {fd.decision.value.upper()}. Reason: {fd.reason}"
            )
        return fd.decision
