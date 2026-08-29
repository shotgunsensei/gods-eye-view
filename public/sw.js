const OFFLINE_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#050a0f"><title>Connection required</title>
<style>:root{color-scheme:dark;font-family:system-ui,sans-serif}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;background:#030608;color:#eafcff}main{max-width:480px;padding:30px;border:1px solid #17616c;border-radius:14px;background:#071319;text-align:center}h1{color:#00f6ff}button{padding:12px 18px;border:0;border-radius:8px;background:#00f6ff;color:#001014;font-weight:800}</style></head>
<body><main><h1>Connection required</h1><p>God's Eye View uses live data and a private server session, so the installed app does not store the protected console for offline use.</p><button onclick="location.reload()">TRY AGAIN</button></main></body></html>`;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  if (event.request.mode !== 'navigate') return;

  event.respondWith(
    fetch(event.request).catch(() => new Response(OFFLINE_PAGE, {
      status: 503,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    })),
  );
});

