#!/usr/bin/env node
/**
 * fw-audit: JSON command-line firewall auditor.
 *
 * Usage:
 *   fw-audit [file.json]      # read policy from file, or stdin when omitted
 *
 * Input JSON:
 *   { "rules": [{ "id": "r1", "action": "allow", "cidr": "10.0.0.0/24" }, ...],
 *     "queries": ["10.0.0.5", ...] }
 *
 * Prints the audit report as JSON. Exits non-zero on invalid input.
 */

import { readFileSync } from "node:fs";
import { ValidationError } from "./audit.js";
import { readStdin, runAudit } from "./runtime.js";

async function main(): Promise<void> {
  const arg = process.argv[2];
  if (!arg && process.stdin.isTTY) {
    process.stderr.write("fw-audit: reading policy from stdin (no file given)\n");
  }
  const text = arg ? readFileSync(arg, "utf8") : await readStdin();

  try {
    const report = runAudit(text);
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } catch (err) {
    if (err instanceof ValidationError) {
      process.stderr.write(`validation error: ${err.message}\n`);
    } else {
      process.stderr.write(`error: ${(err as Error).message}\n`);
    }
    process.exitCode = 1;
  }
}

await main();
