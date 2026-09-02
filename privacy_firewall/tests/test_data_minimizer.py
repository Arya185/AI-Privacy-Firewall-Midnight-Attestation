from pathlib import Path

import pytest

from privacy_firewall import DataMinimizer, PolicyEngine, PolicyViolation
from privacy_firewall.data_minimizer import _MIN_GROUP_SIZE, _aggregate

POLICY_PATH = Path(__file__).parent.parent / "policies" / "analytics_agent.yaml"

# 3 Engineering rows so the demo-1 aggregate meets the k-anonymity floor.
EMPLOYEES = [
    {"name": "Alice", "email": "alice@company.com", "department": "Engineering", "salary": 90000},
    {"name": "Bob", "email": "bob@company.com", "department": "Engineering", "salary": 85000},
    {"name": "Mei", "email": "mei@company.com", "department": "Engineering", "salary": 96000},
    {"name": "Sarah", "email": "sarah@company.com", "department": "HR", "salary": 62000},
]


def engineering_only(records):
    return [r for r in records if r["department"] == "Engineering"]


@pytest.fixture
def minimizer():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    return DataMinimizer(engine)


def test_demo_1_average_salary_never_exposes_raw_values(minimizer):
    """'What is the average salary in Engineering?' should return 90333.33
    over 3 records and must never leak the individual 90000 / 85000 /
    96000 figures or names."""
    records = engineering_only(EMPLOYEES)
    result = minimizer.minimize(
        agent="analytics-agent",
        records=records,
        requested_fields=["employee.department", "employee.salary"],
    )
    assert result.aggregates["employee.salary"]["avg"] == 90333.33
    assert "suppressed" not in result.aggregates["employee.salary"]
    assert result.allowed_fields["employee.department"] == ["Engineering"] * 3
    assert "employee.name" not in result.allowed_fields
    assert "employee.email" not in result.allowed_fields


def test_demo_2_names_and_emails_are_denied(minimizer):
    """'Give me the names and emails of all Engineering employees.'
    Both fields must come back denied, and no values returned."""
    records = engineering_only(EMPLOYEES)
    result = minimizer.minimize(
        agent="analytics-agent",
        records=records,
        requested_fields=["employee.name", "employee.email"],
    )
    assert result.is_denied("employee.name")
    assert result.is_denied("employee.email")
    assert result.allowed_fields == {}
    assert result.aggregates == {}


def test_mixed_request_partitions_correctly(minimizer):
    records = engineering_only(EMPLOYEES)
    result = minimizer.minimize(
        agent="analytics-agent",
        records=records,
        requested_fields=["employee.department", "employee.salary", "employee.name"],
    )
    assert "employee.department" in result.allowed_fields
    assert "employee.salary" in result.aggregates
    assert "employee.name" in result.denied_fields


def test_require_raw_raises_for_aggregate_only_field(minimizer):
    with pytest.raises(PolicyViolation):
        minimizer.require_raw("analytics-agent", "employee.salary")


def test_require_raw_raises_for_denied_field(minimizer):
    with pytest.raises(PolicyViolation):
        minimizer.require_raw("analytics-agent", "employee.email")


def test_require_raw_succeeds_for_allowed_field(minimizer):
    minimizer.require_raw("analytics-agent", "employee.department")  # should not raise


def test_require_raw_raises_for_unmapped_field(minimizer):
    # Fail-closed: a field with no rule in the policy is not ALLOW.
    with pytest.raises(PolicyViolation):
        minimizer.require_raw("analytics-agent", "employee.bonus")


def test_require_raw_raises_for_unknown_agent(minimizer):
    with pytest.raises(PolicyViolation):
        minimizer.require_raw("ghost-agent", "employee.department")


def test_require_raw_audits_the_denied_decision(minimizer):
    with pytest.raises(PolicyViolation):
        minimizer.require_raw("analytics-agent", "employee.email")
    entries = minimizer.audit_log.entries()
    assert len(entries) == 1
    assert entries[0].field == "employee.email"
    assert entries[0].decision.value == "deny"


def test_minimize_never_exposes_a_raw_aggregate_only_column(minimizer):
    result = minimizer.minimize(
        agent="analytics-agent",
        records=EMPLOYEES,
        requested_fields=["employee.salary"],
    )
    # No raw column for an AGGREGATE_ONLY field, anywhere in the result.
    assert "employee.salary" not in result.allowed_fields
    assert [e["salary"] for e in EMPLOYEES] not in result.allowed_fields.values()
    # Only true aggregates. min / max are individual point values and are
    # NOT returned (audit H-1).
    assert set(result.aggregates["employee.salary"]) == {"count", "sum", "avg"}
    assert "min" not in result.aggregates["employee.salary"]
    assert "max" not in result.aggregates["employee.salary"]


def test_aggregate_suppressed_below_min_group():
    # Audit I-1: a single-element group must not disclose the raw scalar.
    out = _aggregate([50000.0])
    assert out["count"] == 1
    assert out["sum"] is None
    assert out["avg"] is None
    assert out["suppressed"] == f"group < k={_MIN_GROUP_SIZE}"


def test_aggregate_computed_at_or_above_min_group():
    out = _aggregate([10.0, 20.0, 30.0])  # len == _MIN_GROUP_SIZE (3)
    assert out == {"count": 3, "sum": 60.0, "avg": 20.0}
    assert "suppressed" not in out
    bigger = _aggregate([2.0, 4.0, 6.0, 8.0])
    assert bigger["sum"] == 20.0 and bigger["avg"] == 5.0


def test_minimize_suppresses_scalar_for_a_sub_k_group(minimizer):
    two_eng = engineering_only(EMPLOYEES)[:2]
    result = minimizer.minimize(
        agent="analytics-agent",
        records=two_eng,
        requested_fields=["employee.salary"],
    )
    agg = result.aggregates["employee.salary"]
    assert agg["count"] == 2 and agg["sum"] is None and agg["avg"] is None
    assert "suppressed" in agg
    # the raw figures still never appear anywhere in the result
    assert 90000 not in agg.values() and 85000 not in agg.values()


def test_every_decision_is_audited(minimizer):
    minimizer.minimize(
        agent="analytics-agent",
        records=EMPLOYEES,
        requested_fields=["employee.department", "employee.salary", "employee.email"],
    )
    logged_fields = {entry.field for entry in minimizer.audit_log.entries()}
    assert logged_fields == {"employee.department", "employee.salary", "employee.email"}
