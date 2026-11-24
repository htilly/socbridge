import express, { type Router } from 'express';
import { z } from 'zod';
import { canRead, type Principal } from '../auth/scopes.js';
import { fixFirst } from '../backends/intel/evidence.js';
import { TIERS } from '../backends/intel/correlate.js';
import type { IntelFeeds } from '../backends/intel/feeds.js';
import { getModule } from '../backends/registry.js';
import type { ToolContext } from '../backends/types.js';
import type { User } from '../config/schema.js';
import { sourceLookup } from '../mcp/server.js';
import { auditView } from './audit-view.js';
import { currentUser, HttpError, requireUser, type AppContext } from './context.js';
import { backendFailure } from './findings.js';

/** A signed-in user reading in the web UI: the same read-only access as the assistant. */
export const webPrincipal = (u: User): Principal => ({ kind: 'chat', id: u.id, userId: u.id, userName: u.name, label: 'web' });

/** The Fix first page: the same function as the intel_fix_first tool. */
export function prioritiesRouter(ctx: AppContext): Router {
  const r = express.Router();

  r.get('/', requireUser, auditView(ctx, () => 'intel'), async (req, res) => {
    const me = currentUser(res);
    const q = z
      .object({
        hours: z.coerce.number().int().min(1).max(168).default(24),
        tier: z.enum(TIERS).optional(),
        service: z.string().trim().max(100).optional(),
        attacked: z.enum(['0', '1']).default('0'),
        fixable: z.enum(['0', '1']).default('0'),
        offset: z.coerce.number().int().min(0).default(0),
        refresh: z.enum(['0', '1']).default('0'),
      })
      .safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid filter');
    if (!canRead(me, 'intel')) throw new HttpError(403, 'You have no read access to Threat intel; ask an administrator');
    const rt = ctx.registry.runtime<IntelFeeds>('intel');
    if (!rt) throw new HttpError(409, 'The Threat intel backend is not enabled');
    const tool: ToolContext = {
      userName: me.name,
      source: sourceLookup(ctx.registry, webPrincipal(me)),
      services: () => ctx.store.get().services,
    };
    try {
      res.json(
        await ctx.registry.gate(getModule('intel')!, rt).run(() =>
          fixFirst(rt, tool, {
            hours: q.data.hours,
            ...(q.data.tier ? { tier: [q.data.tier] } : {}),
            ...(q.data.service ? { service: q.data.service } : {}),
            attacked_only: q.data.attacked === '1',
            fixable_only: q.data.fixable === '1',
            limit: 50,
            offset: q.data.offset,
            refresh: q.data.refresh === '1',
          }),
        ),
      );
    } catch (err) {
      backendFailure(err, res);
    }
  });

  return r;
}
