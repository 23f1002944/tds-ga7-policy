// Node entrypoint — same router as the Worker, for local runs and container hosts.
import { createServer } from 'node:http';
import { handleRequest } from './policy.js';

const port = Number(process.env.PORT || 8787);

export const server = createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);

  const request = new Request(`http://localhost${req.url}`, {
    method: req.method,
    headers: req.headers,
    body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
  });

  const response = await handleRequest(request);
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
});

if (process.env.NODE_ENV !== 'test') {
  server.listen(port, () => console.log(`tds-ga7-policy listening on :${port}`));
}
