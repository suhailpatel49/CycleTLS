const http = require('http');
const net = require('net');
const initCycleTLS = require('../dist/index.js');

test('a stalled TLS handshake obeys the request timeout', async () => {
  const sockets = new Set();
  const server = net.createServer((socket) => sockets.add(socket));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const cycleTLS = await initCycleTLS({ port: 9132 });

  try {
    const started = Date.now();
    const response = await Promise.race([
      cycleTLS(`https://127.0.0.1:${port}/`, { timeout: 1, insecureSkipVerify: true }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('TLS handshake ignored request timeout')), 2500)),
    ]);
    expect(response.status).toBe(408);
    expect(Date.now() - started).toBeLessThan(2500);
  } finally {
    await cycleTLS.exit();
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}, 10000);

test('a paused stream receives a terminal timeout error', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200);
    const chunk = Buffer.alloc(64 * 1024);
    const write = () => {
      while (res.write(chunk));
      res.once('drain', write);
    };
    write();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const cycleTLS = await initCycleTLS({ port: 9133 });

  try {
    const response = await cycleTLS(`http://127.0.0.1:${port}/`, { timeout: 1, responseType: 'stream' });
    const streamError = await Promise.race([
      new Promise((resolve) => response.data.once('error', resolve)),
      new Promise((_, reject) => setTimeout(() => reject(new Error('paused stream never received a terminal event')), 2500)),
    ]);
    expect(streamError.statusCode).toBe(408);
    expect(response.data.destroyed).toBe(true);
  } finally {
    await cycleTLS.exit();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}, 10000);

test('a slow stream does not block other requests', async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/fast') return res.end('ok');
    res.writeHead(200);
    const chunk = Buffer.alloc(64 * 1024);
    let remaining = 128;
    const write = () => {
      while (remaining-- > 0 && res.write(chunk));
      if (remaining > 0) res.once('drain', write);
      else res.end();
    };
    write();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const cycleTLS = await initCycleTLS({ port: 9131 });

  try {
    const slow = await cycleTLS(`http://127.0.0.1:${port}/slow`, { responseType: 'stream' });
    slow.data.on('error', () => {});
    await new Promise((resolve) => setTimeout(resolve, 100));
    const fast = await Promise.race([
      cycleTLS(`http://127.0.0.1:${port}/fast`, { responseType: 'text' }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('fast request blocked by slow stream')), 2000)),
    ]);
    expect(fast.status).toBe(200);
    expect(fast.data).toBe('ok');
    slow.data.destroy();
  } finally {
    await cycleTLS.exit();
    await new Promise((resolve) => server.close(resolve));
  }
}, 10000);
