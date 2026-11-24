import express, { type Router } from 'express';
import { z } from 'zod';
import { newId } from '../auth/secrets.js';
import { suggestServices } from '../backends/intel/suggest.js';
import { MAX_SERVICES, ServiceInputSchema } from '../config/schema.js';
import { auditEvent } from './audit-event.js';
import { sourceLookup } from '../mcp/server.js';
import { currentUser, HttpError, requireAdmin, type AppContext } from './context.js';
import { webPrincipal } from './priorities.js';

/** The service map: administrators only, since it describes the whole environment. */
export function servicesRouter(ctx: AppContext): Router {
  const r = express.Router();
  r.use(requireAdmin);

  const parse = (body: unknown) => {
    const p = ServiceInputSchema.safeParse(body);
    if (!p.success) throw new HttpError(400, p.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
    return p.data;
  };
  const nameTaken = (name: string, except?: string) =>
    ctx.store.get().services.some((s) => s.id !== except && s.name.toLowerCase() === name.toLowerCase());

  r.get('/', (_req, res) => {
    res.json(ctx.store.get().services);
  });

  r.get('/suggestions', async (_req, res) => {
    res.json(await suggestServices(sourceLookup(ctx.registry, webPrincipal(currentUser(res))), ctx.store.get().services));
  });

  r.post('/', async (req, res) => {
    const me = currentUser(res);
    const input = parse(req.body);
    if (nameTaken(input.name)) throw new HttpError(409, `A service named ${input.name} already exists`);
    if (ctx.store.get().services.length >= MAX_SERVICES) throw new HttpError(409, `At most ${MAX_SERVICES} services`);
    const service = { ...input, id: newId() };
    await ctx.store.mutate((d) => {
      d.services.push(service);
    });
    await auditEvent(ctx, { by: me, action: 'admin.service.create', text: 'Service added', details: { id: service.id, name: service.name } });
    res.status(201).json(service);
  });

  r.put('/:id', async (req, res) => {
    const me = currentUser(res);
    const id = z.string().parse(req.params.id);
    const input = parse(req.body);
    if (nameTaken(input.name, id)) throw new HttpError(409, `A service named ${input.name} already exists`);
    const service = await ctx.store.mutate((d) => {
      const i = d.services.findIndex((s) => s.id === id);
      if (i < 0) throw new HttpError(404, 'Unknown service');
      return (d.services[i] = { ...input, id });
    });
    await auditEvent(ctx, { by: me, action: 'admin.service.update', text: 'Service changed', details: { id, name: service.name } });
    res.json(service);
  });

  r.delete('/:id', async (req, res) => {
    const me = currentUser(res);
    const removed = await ctx.store.mutate((d) => {
      const i = d.services.findIndex((s) => s.id === String(req.params.id));
      if (i < 0) throw new HttpError(404, 'Unknown service');
      return d.services.splice(i, 1)[0]!;
    });
    await auditEvent(ctx, { by: me, action: 'admin.service.delete', text: 'Service removed', details: { id: removed.id, name: removed.name } });
    res.status(204).end();
  });

  return r;
}
