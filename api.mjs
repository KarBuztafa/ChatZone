// Mor Sohbet - çevrim dışı mesaj kutusu
// Sunucu mesajların içini GÖREMEZ: istemci mesajı karşı tarafın açık anahtarıyla
// (ECDH P-256 + AES-GCM) şifreleyip gönderir, sunucu sadece şifreli veriyi saklar.

import { getStore } from '@netlify/blobs';
import webpush from 'web-push';
import { createHash, timingSafeEqual } from 'node:crypto';

export const config = { path: '/api/*' };

const MAX_BOX = 200;                 // bir kişinin bekleyen en fazla mesajı
const MAX_LEN = 20000;               // şifreli metin en fazla karakter
const TTL = 14 * 24 * 3600 * 1000;   // 14 gün sonra silinir

const json = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

const sha = (t) => createHash('sha256').update(String(t)).digest('hex');
const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};
const okId = (id) => /^\d{7}$/.test(String(id || ''));
const okJwk = (k) =>
  k && k.kty === 'EC' && k.crv === 'P-256' &&
  typeof k.x === 'string' && typeof k.y === 'string' && k.x.length < 100 && k.y.length < 100;
const okB64 = (s) => typeof s === 'string' && s.length > 0 && s.length <= MAX_LEN && /^[A-Za-z0-9+/=]+$/.test(s);

async function readJson(req) {
  try { return await req.json(); } catch { return {}; }
}

async function getVapid() {
  const cfg = getStore({ name: 'config', consistency: 'strong' });
  let v = await cfg.get('vapid', { type: 'json' });
  if (!v) {
    v = webpush.generateVAPIDKeys();
    await cfg.setJSON('vapid', v);
  }
  return v;
}

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, '') || '/';
  const users = getStore({ name: 'users', consistency: 'strong' });
  const inbox = getStore({ name: 'inbox', consistency: 'strong' });

  async function auth() {
    const id = req.headers.get('x-id');
    const tk = req.headers.get('x-token');
    if (!okId(id) || !tk) return null;
    const u = await users.get('u-' + id, { type: 'json' });
    if (!u || !same(u.th, sha(tk))) return null;
    return { id, u };
  }

  try {
    // Genel: web push açık anahtarı
    if (req.method === 'GET' && path === '/config') {
      const v = await getVapid();
      return json({ vapid: v.publicKey });
    }

    // Genel: bir kişinin açık (public) anahtarı
    if (req.method === 'GET' && path.startsWith('/key/')) {
      const id = path.slice(5);
      if (!okId(id)) return json({ error: 'bad id' }, 400);
      const u = await users.get('u-' + id, { type: 'json' });
      if (!u) return json({ error: 'not found' }, 404);
      return json({ pub: u.pub });
    }

    // Kayıt: numarayı ilk gelen sahiplenir
    if (req.method === 'POST' && path === '/register') {
      const id = req.headers.get('x-id');
      const tk = req.headers.get('x-token');
      const body = await readJson(req);
      if (!okId(id) || !tk || String(tk).length < 16 || !okJwk(body.pub)) return json({ error: 'bad request' }, 400);
      const pub = { kty: body.pub.kty, crv: body.pub.crv, x: body.pub.x, y: body.pub.y };
      const u = await users.get('u-' + id, { type: 'json' });
      if (!u) {
        await users.setJSON('u-' + id, { th: sha(tk), pub, push: null, created: Date.now() });
        return json({ ok: true });
      }
      if (!same(u.th, sha(tk))) return json({ error: 'taken' }, 409);
      u.pub = pub;
      await users.setJSON('u-' + id, u);
      return json({ ok: true });
    }

    // Bildirim aboneliğini kaydet
    if (req.method === 'POST' && path === '/push') {
      const a = await auth();
      if (!a) return json({ error: 'unauthorized' }, 401);
      const body = await readJson(req);
      const s = body.subscription;
      if (!s || typeof s.endpoint !== 'string' || !s.endpoint.startsWith('https://')) return json({ error: 'bad request' }, 400);
      a.u.push = s;
      await users.setJSON('u-' + a.id, a.u);
      return json({ ok: true });
    }

    // Çevrim dışı kişiye şifreli mesaj bırak
    if (req.method === 'POST' && path === '/send') {
      const a = await auth();
      if (!a) return json({ error: 'unauthorized' }, 401);
      const b = await readJson(req);
      if (!okId(b.to) || b.to === a.id || !okB64(b.iv) || !okB64(b.data) || !okJwk(b.spub)) return json({ error: 'bad request' }, 400);
      const rec = await users.get('u-' + b.to, { type: 'json' });
      if (!rec) return json({ error: 'not found' }, 404);

      const { blobs } = await inbox.list({ prefix: b.to + '/' });
      if (blobs.length >= MAX_BOX) return json({ error: 'full' }, 429);

      const key = `${b.to}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      await inbox.setJSON(key, {
        from: a.id,
        iv: b.iv,
        data: b.data,
        spub: { kty: b.spub.kty, crv: b.spub.crv, x: b.spub.x, y: b.spub.y },
        t: Date.now(),
      });

      // Bildirim: içerik yok, sadece "X yazmak istiyor"
      if (rec.push) {
        try {
          const v = await getVapid();
          webpush.setVapidDetails(url.origin, v.publicKey, v.privateKey);
          await webpush.sendNotification(rec.push, JSON.stringify({ from: a.id }), { TTL: 86400 });
        } catch (e) {
          if (e && (e.statusCode === 404 || e.statusCode === 410)) {
            rec.push = null;
            await users.setJSON('u-' + b.to, rec);
          }
        }
      }
      return json({ ok: true });
    }

    // Gelen kutusu
    if (req.method === 'GET' && path === '/inbox') {
      const a = await auth();
      if (!a) return json({ error: 'unauthorized' }, 401);
      const { blobs } = await inbox.list({ prefix: a.id + '/' });
      const now = Date.now();
      const out = [];
      for (const bl of blobs.slice(0, 100)) {
        const m = await inbox.get(bl.key, { type: 'json' });
        if (!m) continue;
        if (now - m.t > TTL) { await inbox.delete(bl.key); continue; }
        out.push({ key: bl.key, from: m.from, iv: m.iv, data: m.data, spub: m.spub, t: m.t });
      }
      out.sort((x, y) => x.t - y.t);
      return json({ messages: out });
    }

    // Teslim alınanları sil
    if (req.method === 'POST' && path === '/ack') {
      const a = await auth();
      if (!a) return json({ error: 'unauthorized' }, 401);
      const body = await readJson(req);
      const keys = Array.isArray(body.keys) ? body.keys.slice(0, 100) : [];
      for (const k of keys) {
        if (typeof k === 'string' && k.startsWith(a.id + '/')) await inbox.delete(k);
      }
      return json({ ok: true });
    }

    return json({ error: 'not found' }, 404);
  } catch (e) {
    return json({ error: 'server error' }, 500);
  }
};
