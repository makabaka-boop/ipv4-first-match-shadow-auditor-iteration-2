/**
 * Policy audit HTTP service.
 *
 *   GET  /healthz  -> { "ok": true }
 *   POST /audit    -> same JSON contract as the CLI, returns the audit report
 *
 * Validation failures get HTTP 400; malformed JSON likewise.
 */

import { createServer, type Server } from "node:http";
import { ValidationError } from "./audit.js";
import { readBody, runAudit } from "./runtime.js";

const PORT = Number(process.env.PORT ?? 3000);

export function createPolicyServer(): Server {
  return createServer((req, res) => {
    const send = (status: number, body: unknown) => {
      const json = JSON.stringify(body);
      res.writeHead(status, {
        "content-type": "application/json; charset=utf-8",
        "content-length": Buffer.byteLength(json),
      });
      res.end(json);
    };

    if (req.method === "GET" && (req.url === "/healthz" || req.url === "/")) {
      send(200, { ok: true, service: "fw-audit-policy" });
      return;
    }

    if (req.method === "POST" && req.url === "/audit") {
      readBody(req)
        .then((text) => {
          try {
            send(200, runAudit(text));
          } catch (err) {
            if (err instanceof ValidationError) {
              send(400, { error: "validation_error", message: err.message });
            } else {
              send(500, { error: "audit_failed", message: (err as Error).message });
            }
          }
        })
        .catch((err: Error) => {
          send(400, { error: "bad_request", message: err.message });
        });
      return;
    }

    send(404, { error: "not_found", message: "use POST /audit" });
  });
}

const server = createPolicyServer();
server.listen(PORT, () => {
  process.stdout.write(`policy service listening on :${PORT}\n`);
});

const shutdown = () => server.close(() => process.exit(0));
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
