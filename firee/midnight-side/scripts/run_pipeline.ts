import { execFileSync } from "child_process";
import { readFileSync } from "fs";

function py(...args: string[]) {
  execFileSync("python3", args, { stdio: "inherit", cwd: "../audit" });
}

async function main() {
  console.log("1/4 generating fake audit log...");
  py("fake_audit_generator.py");

  console.log("2/4 building hash chain...");
  py("hash_chain.py");
  const rootHash = readFileSync("../audit/root_hash.txt", "utf-8").trim();

  console.log("3/4 signing root hash...");
  const signature = execFileSync("python3", ["sign.py", "sign", rootHash], { cwd: "../audit" })
    .toString()
    .trim();

  console.log("4/4 committing to chain...");
  execFileSync("npx", ["tsx", "commit_to_chain.ts"], { stdio: "inherit" });

  console.log("\nVerifying...");
  py("verify.py", "audit_log.jsonl", rootHash, signature);
}

main().catch((err) => {
  console.error("Pipeline failed:", err);
  process.exit(1);
});
