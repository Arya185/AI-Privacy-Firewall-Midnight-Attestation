"""Export a signed attestation batch from a real (offline) firewall run.

Runs two agent requests through the policy engine, then writes the
MidnightBridge batch: one Bytes32 decision hash per policy decision, ready
for policy_attestation.compact's recordAttestation circuit. Nothing leaves
this machine.

    python export_attestation_batch.py [out.json]
"""

import sys
from pathlib import Path

from privacy_firewall.agent import AIAgent, MockEmployeeDB, PrivacyFirewallMiddleware
from privacy_firewall.midnight_bridge import MidnightBridge

out = Path(sys.argv[1] if len(sys.argv) > 1 else "attestation_batch.json")

mw = PrivacyFirewallMiddleware.from_policy_file(
    Path(__file__).parent / "policies" / "analytics_agent.yaml", MockEmployeeDB()
)
agent = AIAgent(mw)
agent.request_aggregate(["department", "salary"], query="avg engineering salary")
agent.request_read(["email", "phone"])

batch = MidnightBridge(mw.audit_log.entries()).export_audit_batch(out)
print(f"{batch['count']} decision hashes -> {out}")
