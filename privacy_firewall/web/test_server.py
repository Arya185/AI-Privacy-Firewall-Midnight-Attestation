"""Tests for the local dashboard backend (web/server.py).

Run from privacy_firewall/:  python -m pytest web -q
Kept outside tests/ so the core suite's documented count is unchanged.
"""

from __future__ import annotations

import http.client
import json
import threading

import pytest

from web import server as srv


@pytest.fixture(scope="module", autouse=True)
def sample_log_untouched():
    before = srv._sha256_file(srv.SAMPLE_LOG) if srv.SAMPLE_LOG.exists() else None
    root_before = srv.ROOT_HASH_FILE.read_text() if srv.ROOT_HASH_FILE.exists() else None
    yield
    if before is not None:
        assert srv._sha256_file(srv.SAMPLE_LOG) == before, "sample audit log was modified"
    if root_before is not None:
        assert srv.ROOT_HASH_FILE.read_text() == root_before, "root_hash.txt was modified"


@pytest.fixture()
def live():
    server = srv.make_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def call(method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=200)
        hdrs = {"Host": f"127.0.0.1:{port}"}
        payload = raw
        if body is not None:
            payload = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        conn.request(method, path, body=payload, headers=hdrs)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        ctype = res.getheader("Content-Type") or ""
        return res.status, (json.loads(data) if ctype.startswith("application/json") else data), res

    yield call
    server.shutdown()
    server.server_close()


AGGREGATE = srv.SAMPLES["requests"][0]["request"]
VIOLATION = srv.SAMPLES["requests"][1]["request"]
UNKNOWN = srv.SAMPLES["requests"][3]["request"]


# ---------------------------------------------------------------- binding & static

def test_server_binds_loopback_only():
    server = srv.make_server(port=0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_index_served_with_security_headers(live):
    status, body, res = live("GET", "/")
    assert status == 200 and b"AI Privacy Firewall" in body
    assert "default-src 'self'" in res.getheader("Content-Security-Policy")
    assert res.getheader("X-Content-Type-Options") == "nosniff"


@pytest.mark.parametrize("path", ["/../server.py", "/static/../server.py", "/etc/passwd", "/app.js/../server.py"])
def test_no_arbitrary_file_access(live, path):
    status, body, _ = live("GET", path)
    assert status == 404


def test_rejects_non_local_host_header(live):
    status, body, _ = live("GET", "/api/status", headers={"Host": "evil.example"})
    assert status == 403


def test_rejects_foreign_origin(live):
    status, _, _ = live("POST", "/api/firewall/request", AGGREGATE, headers={"Origin": "http://evil.example"})
    assert status == 403


# ---------------------------------------------------------------- firewall

def test_aggregate_request_returns_only_statistics(live):
    status, r, _ = live("POST", "/api/firewall/request", AGGREGATE)
    assert status == 200 and r["decision"] == "ALLOW" and r["source"] == "live"
    salary = r["payload"]["aggregates"]["salary"]
    assert set(salary) == {"count", "sum", "avg"}          # no min / max, no raw values
    assert {(f["field"], f["decision"]) for f in r["field_decisions"]} == {
        ("employee.department", "allow"), ("employee.salary", "aggregate_only")}


def test_policy_violation_is_denied(live):
    status, r, _ = live("POST", "/api/firewall/request", VIOLATION)
    assert status == 200 and r["decision"] == "DENY" and r["payload"] is None
    assert all(f["decision"] == "deny" for f in r["field_decisions"])


def test_unknown_agent_fails_closed(live):
    status, r, _ = live("POST", "/api/firewall/request", UNKNOWN)
    assert status == 200 and r["decision"] == "DENY" and r["payload"] is None


@pytest.mark.parametrize("bad", [
    {**AGGREGATE, "operation": "delete"},
    {**AGGREGATE, "fields": []},
    {**AGGREGATE, "fields": ["Salary; DROP"]},
    {**AGGREGATE, "agent_id": "bad agent!"},
    {**AGGREGATE, "query": "x" * 501},
    {k: v for k, v in AGGREGATE.items() if k != "agent_id"},
])
def test_invalid_requests_rejected(live, bad):
    status, r, _ = live("POST", "/api/firewall/request", bad)
    assert status == 400 and "error" in r


def test_malformed_bodies(live):
    assert live("POST", "/api/firewall/request", raw=b"[1,2]", headers={"Content-Type": "application/json"})[0] == 400
    assert live("POST", "/api/firewall/request", raw=b"{nope", headers={"Content-Type": "application/json"})[0] == 400
    assert live("POST", "/api/firewall/request", raw=b"{}", headers={"Content-Type": "text/plain"})[0] == 415
    big = json.dumps({"query": "x" * (srv.MAX_BODY + 10)}).encode()
    assert live("POST", "/api/firewall/request", raw=big, headers={"Content-Type": "application/json"})[0] == 413


def test_output_inspection_blocks_pii_and_masks_canary(live):
    outputs = {o["id"]: o for o in srv.samples()["outputs"]}
    status, r, _ = live("POST", "/api/firewall/inspect", outputs["clean"])
    assert status == 200 and r["decision"] == "ALLOW" and r["output_released"]
    status, r, _ = live("POST", "/api/firewall/inspect", outputs["pii"])
    assert r["decision"] == "BLOCK" and {v["kind"] for v in r["violations"]} == {"pii"}
    status, r, _ = live("POST", "/api/firewall/inspect", outputs["canary"])
    assert r["decision"] == "BLOCK" and any(v["kind"] == "canary" for v in r["violations"])
    for token in srv.CANARY_TOKENS:
        assert token not in json.dumps(r)                  # full canary never echoed back


# ---------------------------------------------------------------- audit

def test_session_chain_grows_and_verifies(live):
    live("POST", "/api/firewall/request", AGGREGATE)
    live("POST", "/api/firewall/request", VIOLATION)
    status, a, _ = live("GET", "/api/audit/session")
    assert status == 200 and a["count"] == 4
    assert all(len(e["request_id"]) <= 9 for e in a["entries"])     # truncated
    status, v, _ = live("POST", "/api/audit/verify", {})
    assert v["session"] == {"source": "live", "entries": 4, "valid": True}
    assert v["sample"]["chain_valid"] is True


def test_session_tamper_demo_detects_and_leaves_original(live):
    live("POST", "/api/firewall/request", AGGREGATE)
    status, t, _ = live("POST", "/api/audit/tamper-demo", {"target": "session", "index": 0})
    assert status == 200 and t["tampered_copy_valid"] is False and t["original_still_valid"] is True


def test_sample_tamper_demo_uses_a_copy(live):
    status, t, _ = live("POST", "/api/audit/tamper-demo", {"target": "sample", "index": 1})
    assert status == 200
    assert t["tampered_copy_valid"] is False and t["original_unchanged"] is True
    assert t["tampered_root_hash"] != t["recorded_root_hash"]
    assert t["signature"]["status"] in ("fail", "unavailable")


def test_tamper_demo_validation(live):
    assert live("POST", "/api/audit/tamper-demo", {"target": "session", "index": 0})[0] == 400   # empty session
    assert live("POST", "/api/audit/tamper-demo", {"target": "disk", "index": 0})[0] == 400
    assert live("POST", "/api/audit/tamper-demo", {"target": "sample", "index": -1})[0] == 400
    assert live("POST", "/api/audit/tamper-demo", {"target": "sample", "index": 10_000})[0] == 400


# ---------------------------------------------------------------- attestation

def test_attestation_view_reports_compiled_contracts(live):
    status, a, _ = live("GET", "/api/attestation")
    assert status == 200 and a["deployment"] == "not deployed"
    names = {c["name"]: c for c in a["contracts"]}
    assert names["policy_attestation"]["circuits"] == ["recordAttestation", "isAttested"]
    assert names["commit"]["circuits"] == ["commit", "get_latest"]


def test_export_hashes_excludes_private_witness(live):
    assert live("POST", "/api/attestation/export", {})[0] == 400          # no decisions yet
    live("POST", "/api/firewall/request", AGGREGATE)
    status, e, _ = live("POST", "/api/attestation/export", {})
    assert status == 200 and e["count"] == 2
    assert all(d["decision_hash"].startswith("0x") and len(d["decision_hash"]) == 66 for d in e["decisions"])
    text = json.dumps(e["decisions"])
    assert "analytics-agent" not in text and "employee." not in text and "private" not in text


@pytest.mark.skipif(srv._npm() is None or not (srv.MIDNIGHT / "node_modules").exists(),
                    reason="Node.js/npm or midnight-side node_modules not installed")
def test_live_simulation_runs_compiled_contracts(live):
    live("POST", "/api/firewall/request", AGGREGATE)
    status, r, _ = live("POST", "/api/attestation/simulate", {})
    assert status == 200 and r["exit_code"] == 0
    assert r["hashes"] == 2 and r["passed"] == 6 and r["failed"] == 0


def test_status_counts_reflect_session(live):
    live("POST", "/api/firewall/request", AGGREGATE)
    live("POST", "/api/firewall/request", VIOLATION)
    status, s, _ = live("GET", "/api/status")
    assert s["session"]["field_decisions"] == {"allow": 1, "aggregate_only": 1, "deny": 2}
    assert s["session"]["chain_valid"] is True and s["firewall"]["healthy"] is True
    live("POST", "/api/session/reset", {})
    assert live("GET", "/api/status")[1]["session"]["total_decisions"] == 0
