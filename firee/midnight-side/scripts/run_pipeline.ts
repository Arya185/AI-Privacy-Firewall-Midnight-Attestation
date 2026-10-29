import { execFileSync } from "child_process";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";

// Resolve relative to this file, not the cwd: `npm run pipeline` runs from the package root.
const AUDIT_DIR = fileURLToPath(new URL("../audit/", import.meta.url));
const COMMIT_SCRIPT = fileURLToPath(new URL("./commit_to_chain.ts", import.meta.url));

function py(...args: string[]) {
  execFileSync("python3", args, { stdio: "inherit", cwd: AUDIT_DIR });
}

async function main() {
  console.log("1/4 generating fake audit log...");
  py("fake_audit_generator.py");

  console.log("2/4 building hash chain...");
  py("hash_chain.py");
  const rootHash = readFileSync(new URL("../audit/root_hash.txt", import.meta.url), "utf-8").trim();

  console.log("3/4 signing root hash...");
  const signature = execFileSync("python3", ["sign.py", "sign", rootHash], { cwd: AUDIT_DIR })
    .toString()
    .trim();

  console.log("4/4 committing to chain...");
  execFileSync("npx", ["tsx", COMMIT_SCRIPT], { stdio: "inherit" });

  console.log("\nVerifying...");
  py("verify.py", "audit_log.jsonl", rootHash, signature);
}

main().catch((err) => {
  console.error("Pipeline failed:", err);
  process.exit(1);
});
