import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { randomBytes } from 'node:crypto';
import { errMessage, log } from '../log.js';
import { GateRejected } from './health.js';
import { BackendError } from './http.js';

/** Upper bound on tool output so a large result cannot flood the model context. */
const MAX_CHARS = 60_000;

export function jsonResult(value: unknown): CallToolResult {
  let text = JSON.stringify(value, null, 2);
  if (text.length > MAX_CHARS) {
    text = text.slice(0, MAX_CHARS) + `\n… [truncated ${text.length - MAX_CHARS} characters; narrow the query or lower the limit]`;
  }
  return { content: [{ type: 'text', text }] };
}

/**
 * Re-caps a tool result that came from elsewhere (Graylog's MCP server): text
 * only, same size limit as our own tools. Images and other content types are
 * replaced by a note rather than forwarded.
 */
export function cappedResult(r: object): CallToolResult {
  const { content, isError } = r as { content?: unknown; isError?: unknown };
  const parts = Array.isArray(content) ? (content as { type?: string; text?: string }[]) : [];
  let text = parts.map((p) => (p.type === 'text' ? (p.text ?? '') : `[${p.type ?? 'unknown'} content omitted]`)).join('\n');
  if (text.length > MAX_CHARS) {
    text = text.slice(0, MAX_CHARS) + `\n… [truncated ${text.length - MAX_CHARS} characters; narrow the query or lower the limit]`;
  }
  return { ...(isError === true ? { isError: true } : {}), content: [{ type: 'text', text: text || '(empty result)' }] };
}

export function errorResult(message: string): CallToolResult {
  return { isError: true, content: [{ type: 'text', text: message }] };
}

/**
 * What a caller who is not an administrator may read about a failure: backend
 * errors name internal hosts and quote responses, other errors can name files.
 */
export function publicError(err: unknown): string {
  if (err instanceof BackendError || err instanceof GateRejected) return err.publicMessage;
  return 'unexpected error';
}

/** Full text of an error whose result says less, for the audit log. */
const details = new WeakMap<CallToolResult, string>();
export const errorDetail = (r: CallToolResult): string | undefined => details.get(r);

/** A tool error for this caller. When text is withheld, a reference ties it to the process log. */
export function failureResult(prefix: string, err: unknown, detailed: boolean): CallToolResult {
  const full = `${prefix}: ${errMessage(err)}`;
  const shown = `${prefix}: ${publicError(err)}`;
  if (detailed || full === shown) return errorResult(full);
  const ref = randomBytes(4).toString('hex');
  log.warn('Tool error', { ref, error: full });
  const out = errorResult(`${shown} (reference ${ref})`);
  details.set(out, `${full} (reference ${ref})`);
  return out;
}

/**
 * Wraps a tool handler so backend failures become MCP tool errors, not
 * protocol errors. `detailed` is for administrators.
 */
export function guard<A>(tool: string, fn: (args: A) => Promise<CallToolResult>, detailed = true): (args: A) => Promise<CallToolResult> {
  return async (args: A) => {
    try {
      return await fn(args);
    } catch (err) {
      if (!(err instanceof BackendError)) log.error('Tool failed', { tool, error: errMessage(err) });
      return failureResult(`${tool} failed`, err, detailed);
    }
  };
}
