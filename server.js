// 心霊写真マップ — Render 用サーバー（Express + PostgreSQL）
"use strict";
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
if (!DATABASE_URL) { console.error("DATABASE_URL is not set"); process.exit(1); }

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: /render\.com|sslmode=require/.test(DATABASE_URL) ? { rejectUnauthorized: false } : false,
  max: 5,
});

const PREFS = ["北海道","青森県","岩手県","宮城県","秋田県","山形県","福島県","茨城県","栃木県","群馬県","埼玉県","千葉県","東京都","神奈川県","新潟県","富山県","石川県","福井県","山梨県","長野県","岐阜県","静岡県","愛知県","三重県","滋賀県","京都府","大阪府","兵庫県","奈良県","和歌山県","鳥取県","島根県","岡山県","広島県","山口県","徳島県","香川県","愛媛県","高知県","福岡県","佐賀県","長崎県","熊本県","大分県","宮崎県","鹿児島県","沖縄県"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// ---------- schema ----------
async function migrate() {
  await pool.query(`
    create table if not exists posts (
      id uuid primary key,
      created_at timestamptz not null default now(),
      title text not null, pref text not null, place text not null default '',
      taken_at date, story text not null default '', nick text not null default '',
      lat double precision not null, lng double precision not null,
      photo bytea not null,
      ip_hash text not null, delete_hash text not null,
      hidden boolean not null default false
    );
    create index if not exists posts_created_idx on posts (created_at desc);
    create table if not exists comments (
      id uuid primary key,
      post_id uuid not null references posts(id) on delete cascade,
      created_at timestamptz not null default now(),
      nick text not null default '', body text not null,
      ip_hash text not null, delete_hash text not null,
      hidden boolean not null default false
    );
    create index if not exists comments_post_idx on comments (post_id, created_at);
    create table if not exists reactions (
      post_id uuid not null references posts(id) on delete cascade,
      client_id text not null,
      fear smallint not null default 0, liked boolean not null default false,
      updated_at timestamptz not null default now(),
      primary key (post_id, client_id)
    );
    create table if not exists reports (
      id bigserial primary key,
      created_at timestamptz not null default now(),
      post_id uuid references posts(id) on delete cascade,
      comment_id uuid references comments(id) on delete cascade,
      reason text not null, ip_hash text not null
    );
    create unique index if not exists reports_once_post on reports (post_id, ip_hash) where comment_id is null;
    create unique index if not exists reports_once_comment on reports (comment_id, ip_hash) where comment_id is not null;
  `);
}

// ---------- helpers ----------
const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const ipHash = (req) => sha256(SECRET + "|" + (req.ip || ""));
const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
async function countSince(table, ip, interval) {
  const { rows } = await pool.query(`select count(*)::int n from ${table} where ip_hash = $1 and created_at > now() - $2::interval`, [ip, interval]);
  return rows[0].n;
}
function signAdmin() {
  const exp = Date.now() + 12 * 3600e3;
  return exp + "." + crypto.createHmac("sha256", SECRET).update("admin:" + exp).digest("hex");
}
function isAdmin(req) {
  const t = String(req.get("authorization") || "").replace(/^Bearer /, "");
  const [exp, sig] = t.split(".");
  if (!exp || !sig || +exp < Date.now()) return false;
  const good = crypto.createHmac("sha256", SECRET).update("admin:" + exp).digest("hex");
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}
const loginTries = new Map();

// ---------- app ----------
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("X-Frame-Options", "SAMEORIGIN");
  next();
});
app.use(express.json({ limit: "8mb" }));

app.get("/healthz", (req, res) => res.send("ok"));

// 投稿一覧（集計つき）
app.get("/api/posts", async (req, res, next) => {
  try {
    const { rows } = await pool.query(`
      select p.id, p.created_at, p.title, p.pref, p.place, to_char(p.taken_at,'YYYY-MM-DD') taken_at, p.story, p.nick, p.lat, p.lng,
        coalesce((select avg(fear)::float from reactions r where r.post_id = p.id and r.fear > 0), 0) fear,
        (select count(*)::int from reactions r where r.post_id = p.id and r.fear > 0) fear_n,
        (select count(*)::int from reactions r where r.post_id = p.id and r.liked) likes,
        (select count(*)::int from comments c where c.post_id = p.id and not c.hidden) comments
      from posts p where not p.hidden order by p.created_at desc limit 2000`);
    res.set("Cache-Control", "no-store").json(rows);
  } catch (e) { next(e); }
});

// 写真
app.get("/photo/:id.jpg", async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.sendStatus(404);
    const { rows } = await pool.query("select photo from posts where id = $1 and (not hidden or $2)", [req.params.id, isAdmin(req)]);
    if (!rows.length) return res.sendStatus(404);
    res.set("Content-Type", "image/jpeg").set("Cache-Control", "public, max-age=604800").send(rows[0].photo);
  } catch (e) { next(e); }
});

// 投稿
app.post("/api/posts", async (req, res, next) => {
  try {
    const b = req.body || {};
    const id = str(b.id, 36), title = str(b.title, 60), pref = str(b.pref, 4);
    const lat = +b.lat, lng = +b.lng;
    if (!UUID.test(id)) return bad(res, "bad id");
    if (!title) return bad(res, "タイトルを入力してください");
    if (!PREFS.includes(pref)) return bad(res, "都道府県を選んでください");
    if (!(lat >= 20 && lat <= 46.5 && lng >= 122 && lng <= 154.5)) return bad(res, "日本国内の地点を指定してください");
    if (!/^[0-9a-f]{64}$/.test(b.delete_hash || "")) return bad(res, "bad hash");
    const taken = /^\d{4}-\d{2}-\d{2}$/.test(b.taken_at || "") ? b.taken_at : null;
    const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(b.photo || "");
    if (!m) return bad(res, "写真の形式が正しくありません");
    const photo = Buffer.from(m[1], "base64");
    if (photo.length > 5 * 1024 * 1024) return bad(res, "写真のサイズが大きすぎます");
    if (photo[0] !== 0xff || photo[1] !== 0xd8) return bad(res, "写真の形式が正しくありません");
    const ip = ipHash(req);
    if (await countSince("posts", ip, "1 hour") >= 5) return bad(res, "短時間に続けて投稿できません（1時間に5件まで）", 429);
    await pool.query(
      `insert into posts (id, title, pref, place, taken_at, story, nick, lat, lng, photo, ip_hash, delete_hash)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, title, pref, str(b.place, 60), taken, str(b.story, 3000), str(b.nick, 24), lat, lng, photo, ip, b.delete_hash]);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === "23505") return bad(res, "すでに投稿されています");
    next(e);
  }
});

// コメント
app.get("/api/posts/:id/comments", async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.json([]);
    const { rows } = await pool.query(
      `select c.id, c.post_id, c.created_at, c.nick, c.body from comments c join posts p on p.id = c.post_id
       where c.post_id = $1 and not c.hidden and not p.hidden order by c.created_at`, [req.params.id]);
    res.set("Cache-Control", "no-store").json(rows);
  } catch (e) { next(e); }
});
app.post("/api/comments", async (req, res, next) => {
  try {
    const b = req.body || {};
    const body = str(b.body, 500);
    if (!UUID.test(b.id || "") || !UUID.test(b.post_id || "")) return bad(res, "bad id");
    if (!body) return bad(res, "コメントを入力してください");
    if (!/^[0-9a-f]{64}$/.test(b.delete_hash || "")) return bad(res, "bad hash");
    const ip = ipHash(req);
    if (await countSince("comments", ip, "10 minutes") >= 10) return bad(res, "短時間に続けて送信できません", 429);
    const r = await pool.query(
      `insert into comments (id, post_id, nick, body, ip_hash, delete_hash)
       select $1, $2, $3, $4, $5, $6 where exists (select 1 from posts where id = $2 and not hidden)`,
      [b.id, b.post_id, str(b.nick, 24), body, ip, b.delete_hash]);
    if (!r.rowCount) return bad(res, "投稿が見つかりません", 404);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// 怖さ評価・ゾッとした
app.post("/api/react", async (req, res, next) => {
  try {
    const b = req.body || {};
    const cid = str(b.client_id, 64), fear = Math.round(+b.fear) || 0, liked = !!b.liked;
    if (!UUID.test(b.post_id || "") || cid.length < 16 || fear < 0 || fear > 5) return bad(res, "invalid");
    if (!fear && !liked) {
      await pool.query("delete from reactions where post_id = $1 and client_id = $2", [b.post_id, cid]);
    } else {
      await pool.query(
        `insert into reactions (post_id, client_id, fear, liked) select $1, $2, $3, $4 where exists (select 1 from posts where id = $1 and not hidden)
         on conflict (post_id, client_id) do update set fear = excluded.fear, liked = excluded.liked, updated_at = now()`,
        [b.post_id, cid, fear, liked]);
    }
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// 通報（3人から通報があれば自動で非表示）
app.post("/api/report", async (req, res, next) => {
  try {
    const b = req.body || {};
    const kind = b.kind === "comment" ? "comment" : "post";
    if (!UUID.test(b.id || "")) return bad(res, "bad id");
    const ip = ipHash(req);
    if (await countSince("reports", ip, "1 hour") >= 20) return bad(res, "短時間に続けて送信できません", 429);
    try {
      await pool.query(`insert into reports (post_id, comment_id, reason, ip_hash) values ($1, $2, $3, $4)`,
        kind === "post" ? [b.id, null, str(b.reason, 300) || "-", ip] : [null, b.id, str(b.reason, 300) || "-", ip]);
    } catch (e) { if (e.code === "23505") return bad(res, "すでに通報済みです", 409); if (e.code === "23503") return bad(res, "見つかりません", 404); throw e; }
    if (kind === "post") {
      await pool.query(`update posts set hidden = true where id = $1 and (select count(distinct ip_hash) from reports where post_id = $1 and comment_id is null) >= 3`, [b.id]);
    } else {
      await pool.query(`update comments set hidden = true where id = $1 and (select count(distinct ip_hash) from reports where comment_id = $1) >= 3`, [b.id]);
    }
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// 本人による削除（投稿時に端末に保存した削除キー）
app.post("/api/posts/:id/delete", async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return bad(res, "bad id");
    const r = await pool.query("delete from posts where id = $1 and delete_hash = $2", [req.params.id, sha256(str((req.body || {}).token, 200))]);
    if (!r.rowCount) return bad(res, "削除できませんでした", 403);
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.post("/api/comments/:id/delete", async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return bad(res, "bad id");
    const r = await pool.query("delete from comments where id = $1 and delete_hash = $2", [req.params.id, sha256(str((req.body || {}).token, 200))]);
    if (!r.rowCount) return bad(res, "削除できませんでした", 403);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---------- 管理者 ----------
app.post("/api/admin/login", (req, res) => {
  const ip = req.ip || "";
  const now = Date.now(), t = (loginTries.get(ip) || []).filter((x) => now - x < 15 * 60e3);
  if (t.length >= 10) return bad(res, "しばらく時間をおいてお試しください", 429);
  t.push(now); loginTries.set(ip, t);
  const pw = String((req.body || {}).password || "");
  if (!ADMIN_PASSWORD || pw.length !== ADMIN_PASSWORD.length ||
      !crypto.timingSafeEqual(Buffer.from(pw), Buffer.from(ADMIN_PASSWORD))) return bad(res, "パスワードが違います", 401);
  loginTries.delete(ip);
  res.json({ token: signAdmin() });
});
const adminOnly = (req, res, next) => (isAdmin(req) ? next() : bad(res, "not admin", 401));
app.get("/api/admin/check", adminOnly, (req, res) => res.json({ ok: true }));
app.get("/api/admin/reports", adminOnly, async (req, res, next) => {
  try {
    const { rows } = await pool.query(`
      select * from (
        select 'post' kind, p.id target_id, p.id post_id, p.title, p.story body, p.hidden, count(r.id)::int reports, string_agg(r.reason, ' / ') reasons, max(r.created_at) last_at
          from posts p join reports r on r.post_id = p.id and r.comment_id is null group by p.id
        union all
        select 'comment', c.id, c.post_id, null, c.body, c.hidden, count(r.id)::int, string_agg(r.reason, ' / '), max(r.created_at)
          from comments c join reports r on r.comment_id = c.id group by c.id
        union all
        select 'post', p.id, p.id, p.title, p.story, p.hidden, 0, '（非表示中）', p.created_at
          from posts p where p.hidden and not exists (select 1 from reports r where r.post_id = p.id)
      ) x order by last_at desc limit 300`);
    res.json(rows);
  } catch (e) { next(e); }
});
app.post("/api/admin/hide", adminOnly, async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!UUID.test(b.id || "")) return bad(res, "bad id");
    const hidden = !!b.hidden;
    if (b.kind === "comment") {
      await pool.query("update comments set hidden = $2 where id = $1", [b.id, hidden]);
      if (!hidden) await pool.query("delete from reports where comment_id = $1", [b.id]);
    } else {
      await pool.query("update posts set hidden = $2 where id = $1", [b.id, hidden]);
      if (!hidden) await pool.query("delete from reports where post_id = $1 and comment_id is null", [b.id]);
    }
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.post("/api/admin/delete", adminOnly, async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!UUID.test(b.id || "")) return bad(res, "bad id");
    await pool.query(b.kind === "comment" ? "delete from comments where id = $1" : "delete from posts where id = $1", [b.id]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---------- static ----------
app.use(express.static(path.join(__dirname, "public"), { maxAge: "5m" }));
app.use((req, res) => res.status(404).send("Not Found"));
app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === "entity.too.large") return bad(res, "写真のサイズが大きすぎます", 413);
  bad(res, "サーバーでエラーが起きました", 500);
});

migrate()
  .then(() => app.listen(PORT, () => console.log("listening on " + PORT)))
  .catch((e) => { console.error("migration failed", e); process.exit(1); });
