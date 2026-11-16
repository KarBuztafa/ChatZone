// Mor Sohbet - servis çalışanı: kapalıyken gelen bildirimleri gösterir
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});

async function nameOf(id){
  try{
    const c = await caches.open('mor-data');
    const r = await c.match('/__friends.json');
    if(r){ const m = await r.json(); if(m[id]) return m[id]; }
  }catch(e){}
  return 'Kişi ' + id;
}

self.addEventListener('push', e => {
  let d = {};
  try{ d = e.data.json(); }catch(_){}
  e.waitUntil((async () => {
    const cl = await self.clients.matchAll({type: 'window', includeUncontrolled: true});
    cl.forEach(c => c.postMessage({t: 'inbox'}));
    if(cl.some(c => c.visibilityState === 'visible')) return;
    const who = d.from ? await nameOf(d.from) : 'Biri';
    await self.registration.showNotification('Mor Sohbet', {
      body: who + ' sana yazmak istiyor',
      tag: 'msg-' + (d.from || 'x'),
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      data: {from: d.from || null}
    });
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type: 'window', includeUncontrolled: true}).then(cl => {
    if(cl.length) return cl[0].focus();
    return self.clients.openWindow('/');
  }));
});
