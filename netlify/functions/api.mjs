import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';

// PERHATIAN: nilai cadangan di bawah hanya aman jika repositori ini PRIVAT.
// Lebih baik isi lewat Netlify > Environment variables, lalu hapus nilai cadangan ini.
const OTP_SECRET = process.env.OTP_SECRET || 'ca29e28edd95bd10ed3a14555cb058077d89bf970d177490';
const FONNTE_TOKEN = process.env.FONNTE_TOKEN || '3pvdjauHffDB1FkWKNX9';
// Hash kode pendaftaran petugas (SHA-256 dari 'warok:' + kode). Bisa diganti lewat PETUGAS_KODE_HASH.
const KODE_H = process.env.PETUGAS_KODE_HASH || '3b227957374699cd045e1abc0cd4f879d6f0311f5bbc7ffa9540739a451e05c1';

// ---------- util ----------
const st = name => getStore({ name, consistency: 'strong' });
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const err = (m, status = 400) => json({ error: m }, status);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hmac = s => crypto.createHmac('sha256', OTP_SECRET).update(s).digest('hex');
const eq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const clean = (v, n) => String(v ?? '').trim().slice(0, n);
const mkPw = pw => { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: crypto.scryptSync(pw, salt, 32).toString('hex') }; };
const okPw = (pw, rec) => !!rec && eq(crypto.scryptSync(pw, rec.salt, 32).toString('hex'), rec.hash);
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normWa = p => { let w = String(p || '').replace(/\D/g, ''); if (w.startsWith('0')) w = '62' + w.slice(1); return /^628\d{7,12}$/.test(w) ? w : null; };

const jakarta = () => Object.fromEntries(new Intl.DateTimeFormat('id-ID', { timeZone: 'Asia/Jakarta', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date()).map(x => [x.type, x.value]));
const nowStr = () => { const p = jakarta(); return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}`; };
const ym = () => { const p = jakarta(); return p.year.slice(2) + p.month; };

// Pembatas percobaan (per kunci, per jendela waktu)
async function limit(key, max, win) {
  const s = st('rl'), k = sha(key).slice(0, 40), now = Date.now();
  let d = await s.get(k, { type: 'json' }).catch(() => null);
  if (!d || now > d.t + win) d = { n: 0, t: now };
  d.n++;
  await s.setJSON(k, d);
  return d.n <= max;
}

// ---------- token login ----------
const sign = o => { const p = Buffer.from(JSON.stringify(o)).toString('base64url'); return p + '.' + hmac('auth:' + p); };
const verify = t => {
  try {
    const [p, s] = String(t).split('.');
    if (!p || !s || !eq(s, hmac('auth:' + p))) return null;
    const o = JSON.parse(Buffer.from(p, 'base64url').toString());
    return o.exp > Date.now() ? o : null;
  } catch { return null; }
};
const authOf = req => verify((req.headers.get('authorization') || '').replace(/^Bearer /, ''));
const SESI = 12 * 3600 * 1000;

// ---------- OTP (stateless: token bertanda tangan, kode tidak pernah dikirim ke browser) ----------
function checkOtp(token, code, wa) {
  try {
    const [p, sig] = String(token).split('.');
    const { wa: w, exp } = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (Date.now() > exp) return 'Kode kedaluwarsa. Kirim ulang.';
    if (w !== wa) return 'Kode tidak sesuai dengan nomor WhatsApp.';
    return eq(sig, hmac(`${w}.${exp}.${String(code).trim()}`)) ? null : 'Kode salah.';
  } catch { return 'Kode tidak valid.'; }
}
async function sendOtp(b, ip) {
  const wa = normWa(b.phone);
  if (!wa) return err('Nomor WhatsApp tidak valid.');
  if (!(await limit('otpip:' + ip, 20, 3600e3)) || !(await limit('otpwa:' + wa, 5, 3600e3))) return err('Terlalu banyak permintaan kode. Coba lagi nanti.', 429);
  const code = String(crypto.randomInt(100000, 1000000));
  const exp = Date.now() + 10 * 60 * 1000;
  const fd = new FormData();
  fd.append('target', wa);
  fd.append('message', `Kode verifikasi WAROK Anda: *${code}*\nBerlaku 10 menit. Jangan bagikan kode ini kepada siapa pun.`);
  const r = await fetch('https://api.fonnte.com/send', { method: 'POST', headers: { Authorization: FONNTE_TOKEN }, body: fd });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || d.status === false) return err('Gagal mengirim WhatsApp.', 502);
  const payload = Buffer.from(JSON.stringify({ wa, exp })).toString('base64url');
  return json({ token: payload + '.' + hmac(`${wa}.${exp}.${code}`) });
}

// ---------- akun warga ----------
function wargaInput(b) {
  const email = clean(b.email, 120).toLowerCase(), nik = clean(b.nik, 16);
  if (!EMAIL.test(email)) return { error: 'Email tidak valid.' };
  if (!/^\d{16}$/.test(nik)) return { error: 'NIK harus 16 digit angka.' };
  return { email, nik };
}
async function wargaTaken(email, nik) {
  const s = st('warga');
  if (await s.get('u:' + email)) return 'Email sudah terdaftar. Silakan masuk.';
  if (await s.get('nik:' + nik)) return 'NIK sudah terdaftar. Satu NIK hanya untuk satu akun.';
  return null;
}
async function wargaCheck(b) {
  const v = wargaInput(b); if (v.error) return err(v.error);
  const t = await wargaTaken(v.email, v.nik); return t ? err(t, 409) : json({ ok: true });
}
async function wargaRegister(b) {
  const v = wargaInput(b); if (v.error) return err(v.error);
  const name = clean(b.name, 100), wa = normWa(b.wa), pw = String(b.password || '');
  if (name.length < 2) return err('Nama lengkap wajib diisi.');
  if (!wa) return err('Nomor WhatsApp tidak valid.');
  if (pw.length < 6 || pw.length > 100) return err('Kata sandi minimal 6 karakter.');
  if (!(await limit('verify:' + wa, 10, 600e3))) return err('Terlalu banyak percobaan. Coba lagi nanti.', 429);
  const o = checkOtp(b.otpToken, b.code, wa); if (o) return err(o);
  const t = await wargaTaken(v.email, v.nik); if (t) return err(t, 409);
  const s = st('warga');
  await s.setJSON('u:' + v.email, { email: v.email, nik: v.nik, name, wa, ...mkPw(pw), created: Date.now() });
  await s.set('nik:' + v.nik, v.email);
  const user = { nik: v.nik, name, wa, email: v.email };
  return json({ token: sign({ role: 'warga', ...user, exp: Date.now() + SESI }), user });
}
async function wargaLogin(b, ip) {
  const email = clean(b.email, 120).toLowerCase();
  if (!(await limit('login:' + email, 10, 900e3)) || !(await limit('loginip:' + ip, 60, 900e3))) return err('Terlalu banyak percobaan masuk. Coba lagi 15 menit lagi.', 429);
  const a = await st('warga').get('u:' + email, { type: 'json' });
  if (!a || !okPw(String(b.password || ''), a)) return err('Email atau kata sandi salah.', 401);
  const user = { nik: a.nik, name: a.name, wa: a.wa, email: a.email };
  return json({ token: sign({ role: 'warga', ...user, exp: Date.now() + SESI }), user });
}

// ---------- akun petugas ----------
async function petugasValid(b) {
  const u = clean(b.user, 20).toLowerCase();
  if (!/^[a-z0-9._]{4,20}$/.test(u)) return { error: 'Nama pengguna 4-20 karakter: huruf kecil, angka, titik, atau garis bawah.' };
  if (await st('petugas').get('u:' + u)) return { error: 'Nama pengguna sudah dipakai.' };
  if (!eq(sha('warok:' + clean(b.kode, 100)), KODE_H)) return { error: 'Kode pendaftaran salah.' };
  return { u };
}
async function petugasCheck(b, ip) {
  if (!(await limit('kode:' + ip, 15, 900e3))) return err('Terlalu banyak percobaan. Coba lagi nanti.', 429);
  const v = await petugasValid(b); return v.error ? err(v.error, 409) : json({ ok: true });
}
async function petugasRegister(b, ip) {
  if (!(await limit('kode:' + ip, 15, 900e3))) return err('Terlalu banyak percobaan. Coba lagi nanti.', 429);
  const v = await petugasValid(b); if (v.error) return err(v.error, 409);
  const name = clean(b.name, 100), wa = normWa(b.wa), pw = String(b.password || '');
  if (name.length < 2) return err('Nama lengkap wajib diisi.');
  if (!wa) return err('Nomor WhatsApp tidak valid.');
  if (pw.length < 8 || pw.length > 100) return err('Kata sandi minimal 8 karakter.');
  if (!(await limit('verify:' + wa, 10, 600e3))) return err('Terlalu banyak percobaan. Coba lagi nanti.', 429);
  const o = checkOtp(b.otpToken, b.code, wa); if (o) return err(o);
  await st('petugas').setJSON('u:' + v.u, { user: v.u, name, nip: clean(b.nip, 30), wa, ...mkPw(pw), created: Date.now() });
  return json({ ok: true });
}
async function petugasLogin(b, ip) {
  const u = clean(b.user, 20).toLowerCase();
  if (!(await limit('plogin:' + u, 10, 900e3)) || !(await limit('loginip:' + ip, 60, 900e3))) return err('Terlalu banyak percobaan masuk. Coba lagi 15 menit lagi.', 429);
  const a = await st('petugas').get('u:' + u, { type: 'json' });
  if (!a || !okPw(String(b.password || ''), a)) return err('Nama pengguna atau kata sandi salah.', 401);
  const user = { user: a.user, name: a.name };
  return json({ token: sign({ role: 'petugas', ...user, exp: Date.now() + SESI }), user });
}

// ---------- berkas (file) ----------
const SVC = ['kk', 'pindah', 'lahir', 'mati'];
const IMG = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const OUT_TYPES = [...IMG, 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
const MAXBYTES = 4_500_000;
const KEYRE = /^[0-9a-f-]{36}$/;
const NIKRE = /^\d{16}$/;
const IDRE = /^WRK-\d{4}-\d{5}$/;

async function uploadFile(u, b) {
  const type = clean(b.type, 100), name = clean(b.name, 160) || 'berkas';
  const owner = u.role === 'warga' ? u.nik : clean(b.forNik, 16);
  if (!NIKRE.test(owner)) return err('Pemilik berkas tidak valid.');
  if (!(u.role === 'petugas' ? OUT_TYPES : [...IMG, 'application/pdf']).includes(type)) return err('Format berkas tidak didukung.');
  const buf = Buffer.from(String(b.data || ''), 'base64');
  if (!buf.length) return err('Berkas kosong.');
  if (buf.length > MAXBYTES) return err('Berkas terlalu besar (maksimal sekitar 3,5 MB).', 413);
  const key = crypto.randomUUID();
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  await st('files').set(key, ab, { metadata: { owner, name, type, size: buf.length, by: u.role } });
  return json({ key, size: buf.length });
}
async function downloadFile(u, url) {
  const key = url.searchParams.get('key') || '';
  if (!KEYRE.test(key)) return err('Berkas tidak ditemukan.', 404);
  const f = await st('files').getWithMetadata(key, { type: 'arrayBuffer' });
  if (!f) return err('Berkas tidak ditemukan.', 404);
  if (u.role === 'warga' && f.metadata?.owner !== u.nik) return err('Tidak diizinkan.', 403);
  return new Response(f.data, { headers: {
    'Content-Type': f.metadata?.type || 'application/octet-stream',
    'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(f.metadata?.name || 'berkas')}`,
    'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': 'sandbox' } });
}

// ---------- pengajuan ----------
async function listReqs(u) {
  const s = st('reqs');
  const { blobs } = await s.list({ prefix: u.role === 'warga' ? `r/${u.nik}/` : 'r/' });
  const all = await Promise.all(blobs.map(x => s.get(x.key, { type: 'json' })));
  return json({ reqs: all.filter(Boolean).sort((a, b) => (b.ts || 0) - (a.ts || 0)) });
}
async function createReq(u, b) {
  if (u.role !== 'warga') return err('Hanya warga yang dapat mengajukan.', 403);
  if (!SVC.includes(b.svc)) return err('Layanan tidak valid.');
  const desa = clean(b.desa, 40); if (!desa) return err('Desa wajib diisi.');
  const fs = st('files'), files = [];
  for (const f of (Array.isArray(b.files) ? b.files.slice(0, 15) : [])) {
    const key = clean(f.key, 40);
    const m = KEYRE.test(key) ? await fs.getMetadata(key) : null;
    if (!m || m.metadata?.owner !== u.nik) return err('Berkas tidak valid. Silakan unggah ulang.');
    files.push({ name: m.metadata.name, label: clean(f.label, 200), key, type: m.metadata.type, size: m.metadata.size });
  }
  const rs = st('reqs'); let id;
  for (let i = 0; i < 5; i++) { id = `WRK-${ym()}-${crypto.randomInt(10000, 100000)}`; if (!(await rs.get(`r/${u.nik}/${id}`))) break; }
  const t = nowStr();
  const r = { id, ts: Date.now(), nik: u.nik, svc: b.svc, jenis: clean(b.jenis, 80), name: clean(b.name, 100) || u.name, wa: clean(b.wa, 20) || u.wa, desa, ket: clean(b.ket, 500), files, date: t, status: 1, times: [t, null, null], outDocs: [] };
  await rs.setJSON(`r/${u.nik}/${id}`, r);
  return json({ req: r });
}
async function loadReq(b) {
  if (!NIKRE.test(String(b.nik)) || !IDRE.test(String(b.id))) return null;
  const key = `r/${b.nik}/${b.id}`;
  const r = await st('reqs').get(key, { type: 'json' });
  return r ? { key, r } : null;
}
async function advance(u, b) {
  if (u.role !== 'petugas') return err('Hanya petugas yang dapat mengubah status.', 403);
  const x = await loadReq(b); if (!x) return err('Pengajuan tidak ditemukan.', 404);
  const n = Number(b.status);
  if (n !== x.r.status + 1 || n > 3) return err('Status sudah berubah. Data dimuat ulang.', 409);
  x.r.status = n; x.r.times[n - 1] = nowStr(); x.r.handledBy = u.name;
  await st('reqs').setJSON(x.key, x.r);
  return json({ req: x.r });
}
async function addOutDoc(u, b) {
  if (u.role !== 'petugas') return err('Hanya petugas yang dapat mengunggah dokumen.', 403);
  const x = await loadReq(b); if (!x) return err('Pengajuan tidak ditemukan.', 404);
  const key = clean(b.key, 40), m = KEYRE.test(key) ? await st('files').getMetadata(key) : null;
  if (!m || m.metadata?.owner !== b.nik) return err('Berkas tidak valid.');
  (x.r.outDocs = x.r.outDocs || []).push({ k: key, name: m.metadata.name, type: m.metadata.type, size: m.metadata.size, at: nowStr() });
  await st('reqs').setJSON(x.key, x.r);
  return json({ req: x.r });
}
async function delOutDoc(u, b) {
  if (u.role !== 'petugas') return err('Hanya petugas yang dapat menghapus dokumen.', 403);
  const x = await loadReq(b); if (!x) return err('Pengajuan tidak ditemukan.', 404);
  const key = clean(b.key, 40);
  if (!(x.r.outDocs || []).some(d => d.k === key)) return err('Dokumen tidak ditemukan.', 404);
  x.r.outDocs = x.r.outDocs.filter(d => d.k !== key);
  await st('reqs').setJSON(x.key, x.r);
  await st('files').delete(key);
  return json({ req: x.r });
}

// ---------- router ----------
export default async (req, context) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\//, '').replace(/\/$/, '');
  const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || 'ip-tidak-diketahui';
  try {
    if (req.method === 'GET') {
      const u = authOf(req); if (!u) return err('Sesi berakhir. Silakan masuk kembali.', 401);
      if (path === 'reqs') return await listReqs(u);
      if (path === 'file') return await downloadFile(u, url);
      return err('Tidak ditemukan.', 404);
    }
    if (req.method !== 'POST') return err('Metode tidak diizinkan.', 405);
    const b = await req.json().catch(() => ({}));
    switch (path) {
      case 'otp-send': return await sendOtp(b, ip);
      case 'warga-check': return await wargaCheck(b);
      case 'warga-register': return await wargaRegister(b);
      case 'warga-login': return await wargaLogin(b, ip);
      case 'petugas-check': return await petugasCheck(b, ip);
      case 'petugas-register': return await petugasRegister(b, ip);
      case 'petugas-login': return await petugasLogin(b, ip);
    }
    const u = authOf(req); if (!u) return err('Sesi berakhir. Silakan masuk kembali.', 401);
    switch (path) {
      case 'file': return await uploadFile(u, b);
      case 'reqs': return await createReq(u, b);
      case 'reqs-advance': return await advance(u, b);
      case 'outdoc': return await addOutDoc(u, b);
      case 'outdoc-delete': return await delOutDoc(u, b);
    }
    return err('Tidak ditemukan.', 404);
  } catch (e) {
    console.error(e);
    return err('Terjadi kesalahan server.', 500);
  }
};

export const config = { path: '/api/*' };
