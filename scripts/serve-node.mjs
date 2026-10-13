// Serve the built Vercel function with plain Node.js, configured from the environment (see .env.example).
// Usage: npm run build:vercel && node scripts/serve-node.mjs [port]
import http from 'node:http';

const { default: handler } = await import('../.vercel/output/functions/index.func/index.mjs');
const port = Number(process.argv[2] ?? process.env.PORT ?? 8787);
http.createServer(handler).listen(port, () => console.log(`Brod on Node at http://localhost:${port}`));
