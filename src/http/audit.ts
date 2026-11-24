import express, { type Router } from 'express';
import { z } from 'zod';
import { insecureUrl, transportPolicy } from '../backends/transport.js';
import { auditEvent } from './audit-event.js';
import { currentUser, HttpError, requireAdmin, requireFresh, type AppContext } from './context.js';

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const r = schema.safeParse(value);
  if (!r.success) throw new HttpError(400, r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
  return r.data;
}

const opt = z
  .string()
  .trim()
  .max(128)
  .optional()
  .transform((v) => v || undefined);

/** A URL without credentials or query, for the log. */
function bareUrl(v: string): string {
  try {
    const u = new URL(v);
    return u.origin + u.pathname;
  } catch {
    return '';
  }
}

/** Audit log of tool calls and administrative events, for administrators only (BACKLOG P1-7). */
export function auditRouter(ctx: AppContext): Router {
  const r = express.Router();

  r.get('/audit', requireAdmin, async (req, res) => {
    const q = parse(
      z.object({
        user: opt,
        tool: opt,
        backend: opt,
        outcome: z.enum(['ok', 'error', 'denied', 'started']).optional(),
        access: z.enum(['read', 'write']).optional(),
        before: z.string().datetime().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(100),
      }),
      req.query,
    );
    const { limit, ...filter } = q;
    const records = await ctx.audit.list(filter, limit);
    res.json({ records, writable: ctx.audit.writable(), next: records.length === limit ? records.at(-1)!.at : null });
  });

  r.get('/audit/stats', requireAdmin, async (req, res) => {
    const { days } = parse(z.object({ days: z.coerce.number().int().min(0).max(3650).default(30) }), req.query);
    const since = days ? new Date(Date.now() - days * 86_400_000).toISOString() : undefined;
    res.json(await ctx.audit.stats(since));
  });

  r.get('/audit/verify', requireAdmin, async (_req, res) => {
    res.json(await ctx.audit.verify());
  });

  r.get('/audit/settings', requireAdmin, (_req, res) => {
    res.json({ gelfUrl: ctx.store.get().server.audit?.gelfUrl ?? '' });
  });

  r.put('/audit/settings', requireAdmin, requireFresh(ctx), async (req, res) => {
    const me = currentUser(res);
    const body = parse(
      z.object({
        gelfUrl: z
          .string()
          .trim()
          .max(500)
          .refine((v) => v === '' || /^https?:\/\/[^\s]+$/i.test(v), 'must be an http(s) URL, e.g. http://graylog:12201/gelf'),
      }),
      req.body,
    );
    if (body.gelfUrl && transportPolicy.requireSecure && insecureUrl(body.gelfUrl)) {
      throw new HttpError(400, 'gelfUrl must be https: this installation requires encrypted connections (REQUIRE_SECURE_TRANSPORT)');
    }
    // Recorded before the change, so the old forwarding target also sees that it is being replaced.
    await auditEvent(ctx, { by: me, action: 'admin.audit.settings', text: 'Audit settings updated', details: { gelf: !!body.gelfUrl, url: bareUrl(body.gelfUrl) } });
    await ctx.store.mutate((draft) => {
      draft.server.audit = { ...draft.server.audit, gelfUrl: body.gelfUrl || undefined };
    });
    res.json({ gelfUrl: body.gelfUrl });
  });

  return r;
}
