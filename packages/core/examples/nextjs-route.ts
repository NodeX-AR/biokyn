// app/api/contact/route.ts  (example; adapt imports to your project)
import { BioKyn, MemoryStore, createChallengeHandler, withBioKyn } from '../src/index';

const engine = new BioKyn({
  secret: process.env['BIOKYN_SECRET']!,
  store: new MemoryStore(),
});

export const GET = createChallengeHandler(engine);
export const POST = withBioKyn(async () => Response.json({ ok: true }), { engine, formId: 'contact' });
