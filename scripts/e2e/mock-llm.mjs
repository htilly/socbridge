// Mock OpenAI-compatible model server (the "local" assistant provider) for the e2e test.
// First call: asks for the socbridge_backends tool. After a tool result: answers with what it saw.
import http from 'node:http';
const PORT = Number(process.env.MOCK_LLM_PORT ?? 19300);
const last = { auth: null, toolNames: [], system: '' };
http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    const send = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.method === 'GET' && req.url.split('?')[0] === '/v1/models') {
      last.modelsKey = req.headers['x-api-key'] ?? req.headers.authorization?.replace(/^Bearer /, '') ?? null;
      return send(200, { data: [{ type: 'model', id: 'mock-model', display_name: 'Mock Model', created_at: '2026-01-01T00:00:00Z' }, { type: 'model', id: 'claude-opus-5-5', display_name: 'Claude Opus 5.5', created_at: '2026-01-01T00:00:00Z' }], has_more: false, first_id: 'mock-model', last_id: 'claude-opus-5-5' });
    }
    if (req.method === 'GET' && req.url === '/last') return send(200, last);
    // Anthropic Messages API shape (the SDK is pointed here with ANTHROPIC_BASE_URL).
    if (req.method === 'GET' && req.url.startsWith('/v1/models/')) return send(200, { type: 'model', id: req.url.slice(11), display_name: 'Mock Claude', created_at: '2026-01-01T00:00:00Z' });
    if (req.method === 'POST' && req.url.startsWith('/v1/messages')) {
      const body = JSON.parse(raw);
      last.anthropic = { key: req.headers['x-api-key'] ?? req.headers.authorization?.replace(/^Bearer /, '') ?? null, beta: req.headers['anthropic-beta'] ?? null, fallbacks: body.fallbacks ?? null, toolNames: (body.tools ?? []).map((t) => t.name), system: body.system?.[0]?.text ?? '', messages: body.messages };
      const lastMsg = body.messages[body.messages.length - 1];
      const result = Array.isArray(lastMsg.content) ? lastMsg.content.find((b) => b.type === 'tool_result') : null;
      const base = { id: 'msg_mock', type: 'message', role: 'assistant', model: body.model, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
      if (!result) return send(200, { ...base, stop_reason: 'tool_use', content: [{ type: 'text', text: 'Checking.' }, { type: 'tool_use', id: 'toolu_1', name: 'socbridge_backends', input: {} }] });
      const enabled = JSON.parse(result.content).filter((b) => b.enabled).map((b) => b.id);
      return send(200, { ...base, stop_reason: 'end_turn', content: [{ type: 'text', text: `Claude says enabled: ${enabled.join(', ')}` }] });
    }
    if (req.method !== 'POST' || req.url !== '/v1/chat/completions') return send(404, { error: { message: 'not found' } });
    const body = JSON.parse(raw);
    last.auth = req.headers.authorization ?? null;
    last.toolNames = (body.tools ?? []).map((t) => t.function.name);
    last.system = body.messages[0]?.role === 'system' ? body.messages[0].content : '';
    const tool = [...body.messages].reverse().find((m) => m.role === 'tool');
    if (!tool) {
      return send(200, { choices: [{ finish_reason: 'tool_calls', message: { role: 'assistant', content: null, tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'socbridge_backends', arguments: '{}' } }] } }] });
    }
    const enabled = JSON.parse(tool.content).filter((b) => b.enabled).map((b) => b.id);
    send(200, { choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: `Enabled backends: ${enabled.join(', ')}` } }] });
  });
}).listen(PORT, '127.0.0.1');
