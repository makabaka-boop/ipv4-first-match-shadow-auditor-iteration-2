/**
 * Shared runtime helpers for the CLI and the HTTP service: reading request
 * bodies and running an audit over JSON text.
 */

import type { IncomingMessage } from "node:http";
import { audit, ValidationError } from "./audit.js";

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin as unknown as AsyncIterable<Buffer>) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function readBody(req: IncomingMessage, maxBytes = 1_000_000): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) {
      throw new ValidationError("request body too large", "$");
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function runAudit(text: string): unknown {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ValidationError(`invalid JSON: ${(err as Error).message}`, "$");
  }
  return audit(raw);
}
