import Anthropic from '@anthropic-ai/sdk';
import { fetch } from 'undici';
import { forbiddenUrl, guardedAgent, readCapped } from '../backends/http.js';
import type { AiProvider, ServerAi } from '../config/schema.js';
import type { ChatTool, ToolOutcome } from './tools.js';

/** One turn of the visible conversation. Tool traffic stays on the server. */
export interface ChatTurn {
  role: 'user' | 'assistant';
  text: string;
}

export type ChatEvent =
  | { type: 'text'; text: string }
  | { type: 'tool'; id: string; name: string; input: unknown }
  | { type: 'tool_done'; id: string; name: string; ok: boolean }
  | { type: 'notice'; text: string }
  | { type: 'done'; provider: AiProvider; model: string; steps: number };

export interface RunOptions {
  system: string;
  history: ChatTurn[];
  tools: ChatTool[];
  callTool: (name: string, input: Record<string, unknown>) => Promise<ToolOutcome>;
  emit: (e: ChatEvent) => void;
  signal: AbortSignal;
  maxSteps: number;
}

export interface ResolvedAi {
  provider: AiProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export const DEFAULT_MODELS: Record<AiProvider, string> = {
  anthropic: 'claude-opus-5-5',
  openai: '',
  local: '',
};
export const DEFAULT_BASE_URLS: Record<AiProvider, string> = {
  anthropic: '',
  openai: 'https://api.openai.com/v1',
  local: '',
};

/** The base URL a provider's requests go to: the given one, or the provider's default. */
export function effectiveBaseUrl(provider: AiProvider, baseUrl: string | undefined): string {
  return (baseUrl?.trim() || DEFAULT_BASE_URLS[provider]).replace(/\/+$/, '');
}

/**
 * Whether the stored key for `provider` may be sent to `baseUrl` (A-005). The
 * Anthropic key only ever goes to Anthropic. Other keys go to the URL they were
 * entered for, or to the provider's own default (api.openai.com); keys stored
 * before keyUrls existed are bound to the saved base URL of their provider.
 */
export function storedKeyMayGoTo(s: ServerAi, provider: AiProvider, baseUrl: string | undefined): boolean {
  if (provider === 'anthropic') return true;
  const target = effectiveBaseUrl(provider, baseUrl);
  if (!target) return false;
  if (DEFAULT_BASE_URLS[provider] && target === DEFAULT_BASE_URLS[provider]) return true;
  const bound = s.keyUrls?.[provider] ?? (s.provider === provider ? effectiveBaseUrl(provider, s.baseUrl) : undefined);
  return bound !== undefined && bound === target;
}

export class AiConfigError extends Error {}

/** Validate the saved settings into something a provider can run, or explain what is missing. */
export function resolveAi(s: ServerAi | undefined): ResolvedAi {
  if (!s?.enabled) throw new AiConfigError('The assistant is turned off. An administrator can enable it under Server.');
  const model = s.model.trim() || DEFAULT_MODELS[s.provider];
  if (!model) throw new AiConfigError('No model is set for this provider.');
  const apiKey = s.keys[s.provider];
  const baseUrl = (s.baseUrl?.trim() || DEFAULT_BASE_URLS[s.provider]).replace(/\/+$/, '');
  if (s.provider !== 'local' && !apiKey) throw new AiConfigError('No API key is stored for this provider.');
  if (s.provider !== 'anthropic' && !baseUrl) throw new AiConfigError('No base URL is set for the local model server.');
  if (apiKey && !storedKeyMayGoTo(s, s.provider, s.baseUrl)) {
    throw new AiConfigError('The stored API key was entered for a different base URL. Enter it again in the assistant settings.');
  }
  return { provider: s.provider, model, apiKey, baseUrl: s.provider === 'anthropic' ? undefined : baseUrl };
}

const asInput = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};

// ---------------------------------------------------------------------------
// Claude (Anthropic SDK)
// ---------------------------------------------------------------------------

/** Models that accept server-side refusal fallbacks (`fallbacks: "default"`). */
const FALLBACK_MODELS = new Set(['claude-fable-5-2', 'claude-fable-5-1', 'claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5']);

async function runAnthropic(ai: ResolvedAi, o: RunOptions): Promise<number> {
  const client = new Anthropic({ apiKey: ai.apiKey, maxRetries: 2 });
  const messages: Anthropic.Beta.BetaMessageParam[] = o.history.map((t) => ({ role: t.role, content: t.text }));
  const tools: Anthropic.Beta.BetaTool[] = o.tools.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: t.inputSchema as Anthropic.Beta.BetaTool.InputSchema,
  }));
  const fallback = FALLBACK_MODELS.has(ai.model);

  let step = 0;
  while (step < o.maxSteps) {
    step++;
    const resp = await client.beta.messages.create(
      {
        model: ai.model,
        max_tokens: 16000,
        system: [{ type: 'text', text: o.system, cache_control: { type: 'ephemeral' } }],
        tools,
        messages,
        ...(fallback ? { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' as const } : {}),
      },
      { signal: o.signal },
    );
    // Keep the full content (thinking blocks included) for the next request.
    messages.push({ role: 'assistant', content: resp.content });

    for (const block of resp.content) {
      if (block.type === 'text' && block.text.trim()) o.emit({ type: 'text', text: block.text });
    }
    if (resp.stop_reason === 'refusal') {
      o.emit({ type: 'notice', text: 'The model declined to answer this request.' });
      break;
    }
    if (resp.stop_reason === 'max_tokens') {
      o.emit({ type: 'notice', text: 'The answer was cut off at the output limit.' });
      break;
    }
    if (resp.stop_reason !== 'tool_use') break;

    const uses = resp.content.filter((b): b is Anthropic.Beta.BetaToolUseBlock => b.type === 'tool_use');
    const results = await Promise.all(
      uses.map(async (u): Promise<Anthropic.Beta.BetaToolResultBlockParam> => {
        o.emit({ type: 'tool', id: u.id, name: u.name, input: u.input });
        const r = await o.callTool(u.name, asInput(u.input));
        o.emit({ type: 'tool_done', id: u.id, name: u.name, ok: !r.isError });
        return { type: 'tool_result', tool_use_id: u.id, content: r.text, is_error: r.isError };
      }),
    );
    // All results of one turn go back in a single user message.
    messages.push({ role: 'user', content: results });
  }
  return step;
}

// ---------------------------------------------------------------------------
// OpenAI and local OpenAI-compatible servers (chat completions over fetch)
// ---------------------------------------------------------------------------

interface OaiToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}
interface OaiMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: OaiToolCall[];
  tool_call_id?: string;
}

/** O-006: the base URL is an administrator's choice, but never a metadata service, and the key stays on it. */
const agent = guardedAgent();
const MAX_ERROR_CHARS = 300;

async function oaiFetch(ai: ResolvedAi, path: string, init: { method: string; body?: string; signal?: AbortSignal }): Promise<unknown> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (ai.apiKey) headers.authorization = `Bearer ${ai.apiKey}`;
  const who = ai.provider === 'local' ? 'Model server' : 'OpenAI';
  const url = new URL(`${ai.baseUrl}${path}`);
  const forbidden = forbiddenUrl(url);
  if (forbidden) throw new Error(`${who}: ${forbidden} and cannot be used`);
  const res = await fetch(url, { ...init, headers, dispatcher: agent, redirect: 'manual' });
  if (res.status >= 300 && res.status < 400) {
    await res.body?.cancel();
    throw new Error(`${who} redirects elsewhere; enter the final base URL`);
  }
  const text = await readCapped(res, url.host);
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = {};
  }
  if (!res.ok) {
    const err = (body as { error?: { message?: string } | string }).error;
    const msg = typeof err === 'string' ? err : (err?.message ?? '');
    throw new Error(`${who} returned HTTP ${res.status}${msg ? `: ${String(msg).slice(0, MAX_ERROR_CHARS)}` : ''}`);
  }
  return body;
}

async function runOpenAiCompatible(ai: ResolvedAi, o: RunOptions): Promise<number> {
  const messages: OaiMessage[] = [{ role: 'system', content: o.system }, ...o.history.map((t) => ({ role: t.role, content: t.text }))];
  const tools = o.tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.inputSchema } }));

  let step = 0;
  while (step < o.maxSteps) {
    step++;
    const body = (await oaiFetch(ai, '/chat/completions', {
      method: 'POST',
      body: JSON.stringify({ model: ai.model, messages, ...(tools.length ? { tools } : {}) }),
      signal: o.signal,
    })) as { choices?: { message?: OaiMessage; finish_reason?: string }[] };
    const choice = body.choices?.[0];
    const msg = choice?.message;
    if (!msg) throw new Error('The model server returned no message.');
    messages.push({ role: 'assistant', content: msg.content ?? null, ...(msg.tool_calls?.length ? { tool_calls: msg.tool_calls } : {}) });

    if (msg.content?.trim()) o.emit({ type: 'text', text: msg.content });
    if (choice.finish_reason === 'length') {
      o.emit({ type: 'notice', text: 'The answer was cut off at the output limit.' });
      break;
    }
    const calls = msg.tool_calls ?? [];
    if (!calls.length) break;

    const results = await Promise.all(
      calls.map(async (c): Promise<OaiMessage> => {
        let input: Record<string, unknown> = {};
        let parseError = false;
        try {
          input = asInput(JSON.parse(c.function.arguments || '{}'));
        } catch {
          parseError = true;
        }
        o.emit({ type: 'tool', id: c.id, name: c.function.name, input });
        const r = parseError
          ? { text: 'Invalid JSON in tool arguments; call the tool again with valid JSON.', isError: true }
          : await o.callTool(c.function.name, input);
        o.emit({ type: 'tool_done', id: c.id, name: c.function.name, ok: !r.isError });
        return { role: 'tool', tool_call_id: c.id, content: r.isError ? `ERROR: ${r.text}` : r.text };
      }),
    );
    messages.push(...results);
  }
  return step;
}

export async function runChat(ai: ResolvedAi, o: RunOptions): Promise<void> {
  const steps = ai.provider === 'anthropic' ? await runAnthropic(ai, o) : await runOpenAiCompatible(ai, o);
  if (steps >= o.maxSteps) o.emit({ type: 'notice', text: `Stopped after ${o.maxSteps} steps. Ask a narrower question to continue.` });
  o.emit({ type: 'done', provider: ai.provider, model: ai.model, steps });
}

/** Cheap check that the key, URL and model work, without generating tokens where possible. */
export async function testAi(ai: ResolvedAi): Promise<string> {
  if (ai.provider === 'anthropic') {
    const client = new Anthropic({ apiKey: ai.apiKey, maxRetries: 0 });
    const m = await client.models.retrieve(ai.model);
    return `Connected to the Claude API. Model ${m.display_name} (${m.id}) is available.`;
  }
  const body = (await oaiFetch(ai, '/models', { method: 'GET', signal: AbortSignal.timeout(15_000) })) as { data?: { id: string }[] };
  const ids = (body.data ?? []).map((m) => m.id);
  if (ids.length && !ids.includes(ai.model)) {
    return `Connected, but model "${ai.model}" is not in the server's list (${ids.slice(0, 8).join(', ')}${ids.length > 8 ? ', …' : ''}).`;
  }
  return `Connected to ${ai.baseUrl}. Model ${ai.model} is available.`;
}

export interface ModelInfo {
  id: string;
  label: string;
}

/** OpenAI lists embeddings, speech, image and moderation models too; none of them can chat. */
const NON_CHAT_OPENAI = /(embedding|whisper|tts|dall-e|davinci|babbage|moderation|transcribe|image|realtime|audio|search|computer-use|sora)/i;

/** The models the provider offers for this key, newest first for Claude, alphabetical otherwise. */
export async function listModels(ai: Omit<ResolvedAi, 'model'>): Promise<ModelInfo[]> {
  if (ai.provider === 'anthropic') {
    const client = new Anthropic({ apiKey: ai.apiKey, maxRetries: 0, timeout: 15_000 });
    const out: ModelInfo[] = [];
    for await (const m of client.models.list({ limit: 100 })) {
      out.push({ id: m.id, label: m.display_name && m.display_name !== m.id ? `${m.display_name} (${m.id})` : m.id });
      if (out.length >= 500) break;
    }
    return out;
  }
  const body = (await oaiFetch({ ...ai, model: '' }, '/models', { method: 'GET', signal: AbortSignal.timeout(15_000) })) as { data?: { id?: unknown }[] };
  const ids = (body.data ?? [])
    .map((m) => (typeof m.id === 'string' ? m.id : ''))
    .filter((id) => id && !(ai.provider === 'openai' && NON_CHAT_OPENAI.test(id)));
  return [...new Set(ids)].sort((a, b) => a.localeCompare(b)).slice(0, 500).map((id) => ({ id, label: id }));
}

/** Turn provider errors into a message that is safe and useful to show. */
export function aiErrorMessage(err: unknown): string {
  if (err instanceof Anthropic.AuthenticationError) return 'The Claude API rejected the API key.';
  if (err instanceof Anthropic.NotFoundError) return 'The Claude API does not know this model.';
  if (err instanceof Anthropic.RateLimitError) return 'The Claude API is rate limiting requests; try again shortly.';
  if (err instanceof Anthropic.APIConnectionError) return 'Could not reach the Claude API.';
  if (err instanceof Anthropic.APIError) return `Claude API error ${err.status ?? ''}: ${err.message}`.trim();
  if (err instanceof Error && err.name === 'AbortError') return 'Cancelled.';
  if (err instanceof TypeError && /fetch failed/i.test(err.message)) {
    const cause = (err as { cause?: { code?: string; message?: string } }).cause;
    return `Could not reach the model server${cause?.code ? ` (${cause.code})` : ''}.`;
  }
  return err instanceof Error ? err.message : String(err);
}
