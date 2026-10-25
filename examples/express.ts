import express from 'express';
import { biokynMiddleware, MemoryStore } from '../src/index';

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(
  biokynMiddleware({
    secret: process.env['BIOKYN_SECRET'] ?? 'dev-only-secret-dev-only-secret-0123456789',
    store: new MemoryStore(),
  }),
);

app.get('/', (_req, res) => {
  res.send(`<!doctype html>
<script src="/__biokyn/client.js" data-base="/__biokyn" defer></script>
<form method="post" action="/contact" data-biokyn="contact">
  <input name="msg" /><button>Send</button>
</form>`);
});

app.post('/contact', (_req, res) => res.send('received'));
app.listen(3000);
