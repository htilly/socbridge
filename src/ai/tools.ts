import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { AuditLog } from '../audit/audit-log.js';
import type { BackendRegistry } from '../backends/registry.js';
import type { User } from '../config/schema.js';
import { buildMcpServer } from '../mcp/server.js';
import { VERSION } from '../version.js';

/** A tool as the chat providers see it: name, description, JSON Schema for the input. */
export interface ChatTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface ToolOutcome {
  text: string;
  isError: boolean;
}

/**
 * The chat uses the very same MCP server as /mcp, connected in-process, as
 * the signed-in user with the `chat` source. That keeps one tool surface and
 * one audit log, and it is read-only by construction (DESIGN §11.3): the
 * server never registers a write tool for the chat, whatever the user's
 * grants, and refuses one again at call time.
 */
export class ToolBridge {
  private constructor(
    private readonly client: Client,
    private readonly close_: () => Promise<void>,
  ) {}

  static async open(registry: BackendRegistry, audit: AuditLog, user: Pick<User, 'id' | 'name'>): Promise<ToolBridge> {
    const { server } = await buildMcpServer(
      registry,
      { kind: 'chat', id: user.id, userId: user.id, userName: user.name, label: 'assistant' },
      { audit, source: 'chat' },
    );
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'socbridge-chat', version: VERSION });
    await server.connect(serverSide);
    await client.connect(clientSide);
    return new ToolBridge(client, async () => {
      await client.close();
      await server.close();
    });
  }

  async list(): Promise<ChatTool[]> {
    const { tools } = await this.client.listTools();
    return tools.map((t) => {
      const { $schema: _drop, ...schema } = t.inputSchema as Record<string, unknown>;
      return { name: t.name, description: t.description ?? t.title ?? t.name, inputSchema: { type: 'object', ...schema } };
    });
  }

  async call(name: string, args: Record<string, unknown>): Promise<ToolOutcome> {
    try {
      const r = await this.client.callTool({ name, arguments: args });
      const parts = (r.content as { type: string; text?: string }[] | undefined) ?? [];
      const text = parts.map((p) => (p.type === 'text' ? (p.text ?? '') : `[${p.type} content omitted]`)).join('\n');
      return { text: text || '(empty result)', isError: r.isError === true };
    } catch (err) {
      return { text: `Tool ${name} failed: ${err instanceof Error ? err.message : String(err)}`, isError: true };
    }
  }

  close(): Promise<void> {
    return this.close_();
  }
}
