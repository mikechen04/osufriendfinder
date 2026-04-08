require("./load-env");

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
let SQLiteStore = null;
try {
  SQLiteStore = require("connect-sqlite3")(session);
} catch (e) {
  // ok, we can still run without it (cloud run etc.)
  SQLiteStore = null;
}

const { osuAuthorizeUrl, osuExchangeCodeForToken, osuGetMe } = require("./osu");
const { rtdb } = require("./firebase");
const OSU_ID_BLACKLIST = require("./blacklist");

const app = express();

// cloud run / reverse proxy — needed so cookies + req.ip work behind https
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const GENDERS = ["male", "female", "enby", "other"];
// partner must be this rank or better (lower osu global_rank number). null = any rank
const RANK_PREF_THRESHOLDS = [1, 100, 500, 1000, 5000, 10000, 50000];
const BIO_MAX = 750;
const ANNOUNCE_TEXT_MAX = 2000;
const ANNOUNCE_MIN_HOURS = 0.25;
const ANNOUNCE_MAX_HOURS = 24 * 30; // 30 days
const ADMIN_OSU_ID = "9632648"; // owner/admin inbox id for reports etc
const ADMIN_SECOND_OSU_ID = "12742221"; // second admin emergency login
const ADMIN_OSU_IDS = new Set(["9632648", "12742221"]);
const ADMIN_EMERGENCY_CODE = (process.env.ADMIN_EMERGENCY_CODE || "").toString().trim();
const ADMIN_EMERGENCY_CODE_FOID = (process.env.ADMIN_EMERGENCY_CODE_FOID || "").toString().trim();

// whole-site freeze: see .env.example
function envTruthy(name) {
  const v = String(process.env[name] || "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}
const SITE_READ_ONLY = envTruthy("SITE_READ_ONLY");
if (SITE_READ_ONLY) {
  console.warn("[site] SITE_READ_ONLY on — logins ok; posting/saving blocked for non-staff");
}
const SLUR_RE = /\bfaggots?\b/i;

function isAdmin(me) {
  if (!me || !me.osu_id) return false;
  return ADMIN_OSU_IDS.has(String(me.osu_id));
}

function badgeCountFromOsuMe(me) {
  if (!me || !Array.isArray(me.badges)) return 0;
  return me.badges.length;
}

// pastel frame on browse + profile for these ppl (match osu username or display name)
const CUTE_TINT_NAMES = new Set(["soft kitten", "chinese foid", "risui", "klbby"]);

// browse stack: these two always first (if they pass filters), then everyone else shuffled
const BROWSE_PIN_ORDER = ["soft kitten", "chinese foid"];

function normCuteName(s) {
  return String(s || "")
    .toLowerCase()
    .trim()
    .replace(/_/g, " ");
}

function userHasCuteTint(username, displayName) {
  const u = normCuteName(username);
  const d = normCuteName(displayName);
  if (u && CUTE_TINT_NAMES.has(u)) return true;
  if (d && CUTE_TINT_NAMES.has(d)) return true;
  return false;
}

function browseUserMatchesPinNorm(u, normPin) {
  if (!u) return false;
  return normCuteName(u.username) === normPin || normCuteName(u.display_name) === normPin;
}

function shuffleArrayCopy(arr) {
  const list = arr.slice();
  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = list[i];
    list[i] = list[j];
    list[j] = tmp;
  }
  return list;
}

// pins come from baseList (after blocks) so they show even if prefs would filter them out
function orderBrowseForDisplay(baseList, filtered) {
  const pinned = [];
  const usedIds = new Set();
  for (const normPin of BROWSE_PIN_ORDER) {
    const u = baseList.find(x => !usedIds.has(String(x.id)) && browseUserMatchesPinNorm(x, normPin));
    if (!u) continue;
    pinned.push(u);
    usedIds.add(String(u.id));
  }
  const rest = filtered.filter(u => !usedIds.has(String(u.id)));
  return pinned.concat(shuffleArrayCopy(rest));
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers && req.headers.cookie ? String(req.headers.cookie) : "";
  if (!raw) return out;
  const parts = raw.split(";");
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function setCookie(res, name, value, opts) {
  const o = opts || {};
  let cookie = `${name}=${encodeURIComponent(value)}`;
  cookie += `; Path=${o.path || "/"}`;
  if (o.maxAgeSeconds != null) cookie += `; Max-Age=${o.maxAgeSeconds}`;
  if (o.httpOnly) cookie += "; HttpOnly";
  if (o.sameSite) cookie += `; SameSite=${o.sameSite}`;
  if (o.secure) cookie += "; Secure";
  // merge like express-session does — if we only used res.append(), getHeader() wouldnt
  // see those cookies and session middleware would setHeader() and wipe admin_override
  const prev = res.getHeader("Set-Cookie") || [];
  const header = Array.isArray(prev) ? prev.concat(cookie) : [prev, cookie];
  res.setHeader("Set-Cookie", header);
}

function clearCookie(res, name) {
  setCookie(res, name, "", { path: "/", maxAgeSeconds: 0, httpOnly: true, sameSite: "Lax", secure: true });
}

function makeOwnerToken(secret) {
  // token lasts 7 days
  const ts = Date.now();
  const sig = crypto.createHmac("sha256", secret).update(String(ts)).digest("hex");
  return `${ts}.${sig}`;
}

function isValidOwnerToken(secret, token) {
  const raw = String(token || "");
  const parts = raw.split(".");
  if (parts.length !== 2) return false;
  const ts = parseInt(parts[0], 10);
  const sig = parts[1];
  if (!Number.isFinite(ts) || !sig) return false;
  const ageMs = Date.now() - ts;
  if (ageMs < 0) return false;
  if (ageMs > 7 * 24 * 60 * 60 * 1000) return false;
  const expected = crypto.createHmac("sha256", secret).update(String(ts)).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch (e) {
    return false;
  }
}

function hasSlur(text) {
  return SLUR_RE.test(String(text || ""));
}

// admin: search all dms for a substring (dedupe in+out copies of same send)
async function adminSearchInboxMessages(keyword) {
  const q = String(keyword || "")
    .trim()
    .toLowerCase();
  if (q.length < 2) {
    return { matches: [], truncated: false, error: "use at least 2 characters" };
  }
  const fdb = rtdb();
  const snap = await fdb.ref("inbox").get();
  if (!snap.exists()) {
    return { matches: [], truncated: false, error: null };
  }
  const all = snap.val();
  const seen = new Set();
  const matches = [];
  for (const [inboxOwnerId, msgs] of Object.entries(all || {})) {
    if (!msgs || typeof msgs !== "object") continue;
    for (const [msgId, m] of Object.entries(msgs)) {
      if (!m || m.body == null) continue;
      const body = String(m.body);
      if (!body.toLowerCase().includes(q)) continue;
      const dedupeKey = `${m.created_at}|${m.from_user_id}|${m.to_user_id}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      matches.push({
        msg_id: msgId,
        inbox_owner_id: String(inboxOwnerId),
        body,
        created_at: m.created_at || 0,
        direction: m.direction || "",
        from_user_id: m.from_user_id ? String(m.from_user_id) : "",
        from_username: m.from_username || "unknown",
        from_osu_id: m.from_osu_id || null,
        to_user_id: m.to_user_id ? String(m.to_user_id) : "",
        to_username: m.to_username || null,
        to_osu_id: m.to_osu_id || null,
      });
    }
  }
  matches.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  let truncated = false;
  if (matches.length > 200) {
    truncated = true;
    matches.splice(200);
  }
  return { matches, truncated, error: null };
}

// admin: full thread between two user ids (only reads inbox/a and inbox/b — not whole tree)
async function adminLoadThreadBetween(userA, userB) {
  const a = String(userA || "").trim();
  const b = String(userB || "").trim();
  if (!a || !b || a === b) {
    return { messages: [], error: "need two different user ids" };
  }
  const fdb = rtdb();
  const [snapA, snapB] = await Promise.all([fdb.ref(`inbox/${a}`).get(), fdb.ref(`inbox/${b}`).get()]);

  const seen = new Set();
  const thread = [];

  function consider(m, inboxOwner) {
    if (!m || m.body == null) return;
    const from = String(m.from_user_id || "");
    const to = String(m.to_user_id || "");
    if (!from || !to) return;
    const pair = new Set([from, to]);
    if (!pair.has(a) || !pair.has(b)) return;
    const dk = `${m.created_at}|${from}|${to}`;
    if (seen.has(dk)) return;
    seen.add(dk);
    thread.push(Object.assign({}, m, { _inbox_owner: inboxOwner }));
  }

  const objA = snapA.exists() ? snapA.val() : {};
  const objB = snapB.exists() ? snapB.val() : {};
  for (const m of Object.values(objA || {})) consider(m, a);
  for (const m of Object.values(objB || {})) consider(m, b);

  thread.sort((x, y) => (x.created_at || 0) - (y.created_at || 0));
  return { messages: thread, error: null };
}

async function createAutoReport({ me, toUserId, toUser, where, text }) {
  const body = String(text || "").slice(0, 500);
  const now = Date.now();
  const ref = rtdb().ref(`reports/${ADMIN_OSU_ID}`).push();
  await ref.set({
    id: ref.key,
    kind: "auto",
    where: where || "unknown",
    from_user_id: me ? String(me.id) : null,
    from_osu_id: me ? me.osu_id : null,
    from_username: me ? me.username : null,
    to_user_id: toUserId ? String(toUserId) : null,
    to_osu_id: toUser ? toUser.osu_id : null,
    to_username: toUser ? toUser.username : null,
    body,
    created_at: now,
  });
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const SESSION_MAX_AGE_MS = parseInt(process.env.SESSION_MAX_AGE_MS || String(14 * 24 * 60 * 60 * 1000), 10);
const SESSION_MAX_AGE_SEC = Math.floor(SESSION_MAX_AGE_MS / 1000);

const sessionOptions = {
  // no need to set SESSION_SECRET in .env for local dev
  secret: process.env.SESSION_SECRET || "osu-edating-local-dev-session-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    maxAge: SESSION_MAX_AGE_MS,
  },
};

if (process.env.NODE_ENV === "production") {
  sessionOptions.cookie.secure = true;
}

// firestore = shared sessions for all cloud run instances (fixes oauth state mismatch)
const useFirestoreSessions = String(process.env.USE_FIRESTORE_SESSIONS || "").trim() === "1";
if (useFirestoreSessions) {
  try {
    const { firestore } = require("./firebase");
    const FirestoreSessionStore = require("./firestore-session-store");
    const coll = (process.env.FIRESTORE_SESSION_COLLECTION || "express_sessions").trim() || "express_sessions";
    sessionOptions.store = new FirestoreSessionStore(firestore(), {
      collection: coll,
      ttlSeconds: SESSION_MAX_AGE_SEC,
    });
    console.log("[session] firestore store:", coll);
  } catch (e) {
    console.error("[session] firestore failed, falling back to memory (logins may break on multi-instance)", e);
  }
} else if (process.env.NODE_ENV !== "production" && SQLiteStore) {
  // local dev: sqlite file
  sessionOptions.store = new SQLiteStore({
    db: "sessions.sqlite",
    dir: path.join(__dirname, "data"),
  });
} else if (process.env.NODE_ENV === "production" && !sessionOptions.store) {
  console.warn(
    "[session] in-memory store on production — set USE_FIRESTORE_SESSIONS=1 after enabling Firestore for reliable osu login"
  );
}

app.use(session(sessionOptions));

// attach user info for templates
app.use(async (req, res, next) => {
  try {
    // emergency override cookies (dont rely on in-memory sessions)
    if (!req.session || !req.session.userId) {
      const cookies = parseCookies(req);
      if (ADMIN_EMERGENCY_CODE) {
        const token = cookies.admin_override || "";
        if (token && isValidOwnerToken(ADMIN_EMERGENCY_CODE, token)) {
          if (req.session) req.session.userId = ADMIN_OSU_ID;
        }
      }
      if ((!req.session || !req.session.userId) && ADMIN_EMERGENCY_CODE_FOID) {
        const tokenF = cookies.admin_override_foid || "";
        if (tokenF && isValidOwnerToken(ADMIN_EMERGENCY_CODE_FOID, tokenF)) {
          if (req.session) req.session.userId = ADMIN_SECOND_OSU_ID;
        }
      }
    }

    res.locals.me = null;
    res.locals.inboxUnread = null;
    res.locals.prefs = null;
    res.locals.isAdmin = false;

    if (req.session && req.session.userId) {
      const userId = String(req.session.userId);
      const fdb = rtdb();

      // dynamic ban list in rtdb + static file blacklist — kick session so they cant keep browsing
      const banSnap = await fdb.ref(`osu_bans/${userId}`).get();
      if (banSnap.exists() || OSU_ID_BLACKLIST.has(userId)) {
        clearCookie(res, "admin_override");
        clearCookie(res, "admin_override_foid");
        return req.session.destroy(() => {
          res.redirect("/?banned=1");
        });
      }

      const userSnap = await fdb.ref(`users/${userId}`).get();
      const profileSnap = await fdb.ref(`profiles/${userId}`).get();
      const inboxSnap = await fdb.ref(`inbox/${userId}`).get();
      const prefsSnap = await fdb.ref(`prefs/${userId}`).get();

      const user = userSnap.exists() ? userSnap.val() : null;
      const profile = profileSnap.exists() ? profileSnap.val() : null;
      const inboxObj = inboxSnap.exists() ? inboxSnap.val() : {};
      const prefs = prefsSnap.exists() ? prefsSnap.val() : null;

      if (user) {
        res.locals.me = {
          id: userId,
          osu_id: user.osu_id,
          username: user.username,
          avatar_url: user.avatar_url || null,
          country_code: user.country_code || null,
          global_rank: user.global_rank || null,
          badge_count: typeof user.badge_count === "number" ? user.badge_count : null,
          age: profile ? profile.age : null,
          bio: profile ? profile.bio : null,
          gender: profile ? profile.gender : null,
          discord: profile ? profile.discord : null,
          display_name: profile ? profile.display_name : null,
          cute_tint: userHasCuteTint(user.username, profile ? profile.display_name : null),
        };
        res.locals.prefs = prefs;
        res.locals.isAdmin = isAdmin(res.locals.me);

        // count unread messages
        let unread = 0;
        for (const m of Object.values(inboxObj || {})) {
          if (m && !m.read_at) unread += 1;
        }
        res.locals.inboxUnread = unread;
      }
    }

    res.locals.siteAnnouncement = null;
    try {
      const annSnap = await rtdb().ref("site/announcement").get();
      if (annSnap.exists()) {
        const v = annSnap.val();
        const annText = (v.text || "").toString().trim();
        const exp = Number(v.expires_at);
        if (annText && Number.isFinite(exp) && exp > Date.now()) {
          res.locals.siteAnnouncement = { text: annText, expires_at: exp };
        }
      }
    } catch (annErr) {
      console.error(annErr);
    }

    res.locals.flash = req.session.flash || null;
    req.session.flash = null;
    next();
  } catch (e) {
    console.error(e);
    res.locals.me = null;
    res.locals.isAdmin = false;
    res.locals.flash = null;
    res.locals.siteAnnouncement = null;
    next();
  }
});

// so ejs + sendHomeHtml can show a banner
app.use((req, res, next) => {
  res.locals.siteReadOnly = SITE_READ_ONLY;
  next();
});

// read-only: block form posts for normal users (osu login + guest enter still allowed)
function redirectSameOriginRefererOrHome(req, res) {
  const ref = req.get("Referer");
  if (ref) {
    try {
      const u = new URL(ref);
      const hostRaw = req.get("x-forwarded-host") || req.get("host") || "";
      const host = hostRaw.split(",")[0].trim();
      if (host && u.host === host) {
        return res.redirect(u.pathname + u.search);
      }
    } catch (e) {
      // ignore bad referer
    }
  }
  res.redirect("/");
}

function readOnlyBlockWrites(req, res, next) {
  if (!SITE_READ_ONLY) return next();
  // staff can do anything
  if (res.locals.isAdmin) return next();

  const p = req.path || "";

  const m = req.method;
  if (m !== "POST" && m !== "PUT" && m !== "PATCH" && m !== "DELETE") {
    return next();
  }

  if (p === "/logout") return next();
  if (p === "/emergency-login" || p === "/emergency-foid-login") return next();
  if (p === "/enter") return next();
  if (p === "/guest/exit") return next();

  req.session.flash = {
    type: "warn",
    message: "site is read-only right now — nothing was saved",
  };
  return redirectSameOriginRefererOrHome(req, res);
}

app.use(readOnlyBlockWrites);

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect("/");
  }
  next();
}

// must be logged in; res.locals.me must be a site admin (use after requireAuth)
function requireAdmin(req, res, next) {
  if (!isAdmin(res.locals.me)) return res.redirect("/");
  next();
}

// lock down all /admin/... routes in one place (announcements, messages, wipe, etc.)
function requireAdminSection(req, res, next) {
  const p = req.path || "";
  if (!p.startsWith("/admin/")) return next();
  requireAuth(req, res, () => requireAdmin(req, res, next));
}

app.use(requireAdminSection);

function requireAuthOrGuest(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.session && req.session.guestOk) return next();
  return res.redirect("/enter");
}

function requireProfile(req, res, next) {
  const me = res.locals.me;
  if (!me) return res.redirect("/");
  if (!me.age || !me.bio || !me.gender) {
    req.session.flash = {
      type: "warn",
      message: "finish your profile first so ppl know who u are",
    };
    return res.redirect("/profile/edit");
  }
  next();
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// home page is root index.html (same folder as Dockerfile) — inject flash for oauth errors etc.
function sendHomeHtml(req, res) {
  const htmlPath = path.join(__dirname, "index.html");
  let html = fs.readFileSync(htmlPath, "utf8");
  let flash = res.locals.flash;
  // after session destroy we can still show why they got kicked (instaban etc.)
  if (!flash && req.query && String(req.query.banned) === "1") {
    flash = { type: "error", message: "u are blocked from using this site" };
  }
  const ann = res.locals.siteAnnouncement;
  let annBlock = "";
  if (ann && ann.text) {
    const until = new Date(ann.expires_at).toLocaleString();
    annBlock = `<div class="site-announcement" role="status"><div class="site-announcement-inner"><span class="site-announcement-label">announcement</span><p class="site-announcement-text">${escapeHtml(ann.text)}</p><span class="site-announcement-until">shows until ${escapeHtml(until)}</span></div></div>`;
  }
  html = html.replace("<!--ANNOUNCEMENT-->", annBlock);
  let roBlock = "";
  const showRoBanner =
    SITE_READ_ONLY && !(res.locals.me && isAdmin(res.locals.me));
  if (showRoBanner) {
    roBlock =
      '<div class="site-readonly-banner" role="status"><div class="site-readonly-inner">read-only mode — you can browse and sign in, but sending messages and saving changes are off</div></div>';
  }
  html = html.replace("<!--READONLY-->", roBlock);
  if (flash) {
    html = html.replace(
      "<!--FLASH-->",
      `<div class="flash ${flash.type}">${escapeHtml(flash.message)}</div>`
    );
  } else {
    html = html.replace("<!--FLASH-->", "");
  }
  res.type("html").send(html);
}

app.get("/api/me", (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.userId) });
});

app.get("/api/featured", requireAuth, async (req, res) => {
  try {
    const me = res.locals.me;
    const userId = me ? String(me.id) : String(req.session.userId);
    const fdb = rtdb();
    // admins see everyone on home showcase too (no block filter)
    const adminSeeAll = me && isAdmin(me);

    const [usersSnap, profilesSnap, blocksSnap] = await Promise.all([
      fdb.ref("users").get(),
      fdb.ref("profiles").get(),
      adminSeeAll ? Promise.resolve(null) : fdb.ref(`blocks/${userId}`).get(),
    ]);

    const usersObj = usersSnap.exists() ? usersSnap.val() : {};
    const profilesObj = profilesSnap.exists() ? profilesSnap.val() : {};
    const blocksObj = blocksSnap && blocksSnap.exists() ? blocksSnap.val() : {};
    const blockedIds = adminSeeAll ? new Set() : new Set(Object.keys(blocksObj || {}));

    let list = [];
    for (const [id, u] of Object.entries(usersObj || {})) {
      if (!u) continue;
      if (String(id) === String(userId)) continue;
      if (blockedIds.has(String(id))) continue;
      const p = profilesObj ? profilesObj[id] : null;
      if (!p) continue;
      if (!adminSeeAll && (!p.age || !p.bio || !p.gender)) continue;

      list.push({
        id: String(id),
        osu_id: u.osu_id,
        username: u.username,
        avatar_url: u.avatar_url || null,
        country_code: u.country_code || null,
        global_rank: u.global_rank || null,
        badge_count: typeof u.badge_count === "number" ? u.badge_count : null,
        age: p.age,
        gender: p.gender || null,
        bio: (p.bio || "").slice(0, 120),
        cute_tint: userHasCuteTint(u.username, p.display_name),
      });
    }

    // shuffle so older users dont get buried
    for (let i = list.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      const tmp = list[i];
      list[i] = list[j];
      list[j] = tmp;
    }

    res.json({ users: list.slice(0, 9) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ users: [] });
  }
});

app.get("/", (req, res) => {
  sendHomeHtml(req, res);
});

app.get("/index.html", (req, res) => {
  sendHomeHtml(req, res);
});

app.get("/enter", (req, res) => {
  // already in? go browse
  if (req.session && (req.session.userId || req.session.guestOk)) return res.redirect("/browse");
  res.render("pages/enter", { title: "enter" });
});

// emergency owner login (bypasses osu oauth during traffic)
app.get("/emergency", (req, res) => {
  res.render("pages/emergency", { title: "emergency" });
});

app.post("/emergency-login", (req, res) => {
  const code = (req.body.code || "").toString().trim();

  if (!ADMIN_EMERGENCY_CODE) {
    req.session.flash = { type: "error", message: "admin emergency code not set" };
    return res.redirect("/");
  }

  if (code !== ADMIN_EMERGENCY_CODE) {
    req.session.flash = { type: "error", message: "wrong code" };
    return res.redirect("/emergency");
  }

  // log in as owner (cookie-based so it works across cloud run instances)
  clearCookie(res, "admin_override_foid");
  if (req.session) req.session.userId = ADMIN_OSU_ID;
  const token = makeOwnerToken(ADMIN_EMERGENCY_CODE);
  setCookie(res, "admin_override", token, {
    path: "/",
    maxAgeSeconds: 7 * 24 * 60 * 60,
    httpOnly: true,
    sameSite: "Lax",
    secure: true,
  });

  req.session.flash = { type: "ok", message: "owner login ok" };
  return res.redirect("/preferences");
});

// second admin emergency (12742221)
app.get("/emergency-foid", (req, res) => {
  res.render("pages/emergency_foid", { title: "emergency" });
});

app.post("/emergency-foid-login", (req, res) => {
  const code = (req.body.code || "").toString().trim();

  if (!ADMIN_EMERGENCY_CODE_FOID) {
    req.session.flash = { type: "error", message: "foid emergency code not set" };
    return res.redirect("/");
  }

  if (code !== ADMIN_EMERGENCY_CODE_FOID) {
    req.session.flash = { type: "error", message: "wrong code" };
    return res.redirect("/emergency-foid");
  }

  clearCookie(res, "admin_override");
  if (req.session) req.session.userId = ADMIN_SECOND_OSU_ID;
  const token = makeOwnerToken(ADMIN_EMERGENCY_CODE_FOID);
  setCookie(res, "admin_override_foid", token, {
    path: "/",
    maxAgeSeconds: 7 * 24 * 60 * 60,
    httpOnly: true,
    sameSite: "Lax",
    secure: true,
  });

  req.session.flash = { type: "ok", message: "admin login ok" };
  return res.redirect("/preferences");
});

app.post("/enter", (req, res) => {
  const code = (req.body.code || "").toString().trim();
  if (code === "taikichan") {
    req.session.guestOk = true;
    req.session.flash = { type: "ok", message: "ok u can browse" };
    return res.redirect("/browse");
  }
  req.session.flash = { type: "error", message: "wrong code" };
  return res.redirect("/enter");
});

app.get("/auth/osu", (req, res) => {
  try {
    const state = crypto.randomBytes(24).toString("hex");
    req.session.osuState = state;
    res.redirect(osuAuthorizeUrl(state));
  } catch (err) {
    console.error(err);
    req.session.flash = {
      type: "error",
      message:
        "missing osu! oauth keys. check .env in the project folder has OSU_CLIENT_ID (and restart the server)",
    };
    res.redirect("/");
  }
});

app.get("/auth/osu/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code) {
      req.session.flash = { type: "error", message: "missing auth code :(" };
      return res.redirect("/");
    }

    if (!state || !req.session.osuState || state !== req.session.osuState) {
      req.session.flash = { type: "error", message: "state mismatch (sus)" };
      return res.redirect("/");
    }

    // clear it so it cant be reused
    req.session.osuState = null;

    const token = await osuExchangeCodeForToken(code);
    const me = await osuGetMe(token.access_token);

    // block blacklisted osu ids (ex: minors) + instabans from profile age attempts
    const osuIdStr = String(me.id);
    const banSnap = await rtdb().ref(`osu_bans/${osuIdStr}`).get();
    if (OSU_ID_BLACKLIST.has(osuIdStr) || banSnap.exists()) {
      req.session.userId = null;
      req.session.flash = { type: "error", message: "u are blocked from using this site" };
      return res.redirect("/");
    }

    // store user in rtdb using osu id as the key (stable on cloud run)
    const userId = String(me.id);
    const now = Date.now();
    await rtdb().ref(`users/${userId}`).update({
      osu_id: me.id,
      username: me.username,
      avatar_url: me.avatar_url || null,
      country_code: me.country_code || null,
      global_rank: (me && me.statistics && me.statistics.global_rank) ? me.statistics.global_rank : null,
      badge_count: badgeCountFromOsuMe(me),
      updated_at: now,
      created_at: now,
    });

    req.session.userId = userId;

    return res.redirect("/preferences");
  } catch (err) {
    console.error(err);
    req.session.flash = {
      type: "error",
      message: "osu! login failed. too much traffic on the server just wait or try again",
    };
    return res.redirect("/");
  }
});

app.post("/logout", (req, res) => {
  // clear emergency override cookies
  clearCookie(res, "admin_override");
  clearCookie(res, "admin_override_foid");
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// quick way to clear guest access if needed
app.post("/guest/exit", (req, res) => {
  if (req.session) req.session.guestOk = null;
  res.redirect("/");
});

app.post("/block", requireAuth, async (req, res) => {
  const me = res.locals.me;
  const blockUserId = (req.body.block_user_id || "").toString().trim();
  const redirectTo = (req.body.redirect_to || "").toString().trim();

  if (!me) return res.redirect("/");
  if (!blockUserId) {
    req.session.flash = { type: "error", message: "nothing to block" };
    return res.redirect(redirectTo || "/browse");
  }
  if (String(blockUserId) === String(me.id)) {
    req.session.flash = { type: "error", message: "u cant block urself" };
    return res.redirect(redirectTo || "/browse");
  }

  try {
    await rtdb().ref(`blocks/${String(me.id)}/${String(blockUserId)}`).set(true);
    req.session.flash = { type: "ok", message: "blocked" };
    return res.redirect(redirectTo || "/browse");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to block" };
    return res.redirect(redirectTo || "/browse");
  }
});

app.post("/report", requireAuth, async (req, res) => {
  const me = res.locals.me;
  const toUserId = (req.body.to_user_id || "").toString().trim();
  const bodyRaw = (req.body.body || "").toString().trim();
  const body = bodyRaw.slice(0, 500);

  if (!me) return res.redirect("/");
  if (!toUserId) {
    req.session.flash = { type: "error", message: "invalid report target" };
    return res.redirect("/browse");
  }
  if (!body || body.length < 3) {
    req.session.flash = { type: "error", message: "report is too short" };
    return res.redirect("/browse");
  }

  try {
    if (hasSlur(bodyRaw)) {
      // still save it, but mark as auto as well (so it stands out)
      await createAutoReport({
        me,
        toUserId,
        toUser: null,
        where: "report",
        text: bodyRaw,
      });
    }

    const fdb = rtdb();
    const toUserSnap = await fdb.ref(`users/${toUserId}`).get();
    const toUser = toUserSnap.exists() ? toUserSnap.val() : null;

    const now = Date.now();
    const ref = fdb.ref(`reports/${ADMIN_OSU_ID}`).push();
    await ref.set({
      id: ref.key,
      kind: "user",
      from_user_id: String(me.id),
      from_osu_id: me.osu_id,
      from_username: me.username,
      to_user_id: String(toUserId),
      to_osu_id: toUser ? toUser.osu_id : null,
      to_username: toUser ? toUser.username : null,
      body,
      created_at: now,
    });

    req.session.flash = { type: "ok", message: "report sent" };
    return res.redirect("/browse");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to send report" };
    return res.redirect("/browse");
  }
});

app.get("/preferences", requireAuth, async (req, res) => {
  try {
    const me = res.locals.me;
    const userId = me ? String(me.id) : String(req.session.userId);
    const fdb = rtdb();

    const blocksSnap = await fdb.ref(`blocks/${userId}`).get();
    const blocksObj = blocksSnap.exists() ? blocksSnap.val() : {};
    const blockedIds = Object.keys(blocksObj || {});

    let blockedUsers = [];
    if (blockedIds.length) {
      // basic way: just read all users once and pick the ones we need
      const usersSnap = await fdb.ref("users").get();
      const usersObj = usersSnap.exists() ? usersSnap.val() : {};

      blockedUsers = blockedIds.map(id => {
        const u = usersObj && usersObj[id] ? usersObj[id] : null;
        return {
          id: String(id),
          username: u && u.username ? u.username : "unknown",
          osu_id: u && u.osu_id ? u.osu_id : id,
          avatar_url: u && u.avatar_url ? u.avatar_url : null,
        };
      });
    }

    let reports = [];
    if (isAdmin(me)) {
      const repSnap = await fdb.ref(`reports/${ADMIN_OSU_ID}`).get();
      const repObj = repSnap.exists() ? repSnap.val() : {};
      reports = Object.values(repObj || {});
      reports.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
      reports = reports.slice(0, 50);
    }

    res.render("pages/preferences", { title: "preferences", blockedUsers, reports });
  } catch (e) {
    console.error(e);
    res.render("pages/preferences", { title: "preferences", blockedUsers: [], reports: [] });
  }
});

app.post("/admin/announcement", async (req, res) => {
  const me = res.locals.me;
  const text = (req.body.announcement_text || "").toString().trim().slice(0, ANNOUNCE_TEXT_MAX);
  const hours = parseFloat(String(req.body.duration_hours || "").trim());

  if (!text) {
    req.session.flash = { type: "error", message: "write something or use clear announcement" };
    return res.redirect("/preferences");
  }

  if (!Number.isFinite(hours) || hours < ANNOUNCE_MIN_HOURS || hours > ANNOUNCE_MAX_HOURS) {
    req.session.flash = {
      type: "error",
      message: `duration must be ${ANNOUNCE_MIN_HOURS}–${ANNOUNCE_MAX_HOURS} hours`,
    };
    return res.redirect("/preferences");
  }

  const now = Date.now();
  const expires_at = now + hours * 60 * 60 * 1000;
  try {
    await rtdb().ref("site/announcement").set({
      text,
      expires_at,
      updated_at: now,
      updated_by: me && me.username ? me.username : null,
    });
    req.session.flash = { type: "ok", message: "announcement posted" };
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to save announcement" };
  }
  return res.redirect("/preferences");
});

app.post("/admin/announcement/clear", async (req, res) => {
  try {
    await rtdb().ref("site/announcement").set(null);
    req.session.flash = { type: "ok", message: "announcement cleared" };
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to clear" };
  }
  return res.redirect("/preferences");
});

app.post("/admin/reports/done", async (req, res) => {
  const reportId = (req.body.report_id || "").toString().trim();
  if (!reportId) return res.redirect("/preferences");

  try {
    await rtdb().ref(`reports/${ADMIN_OSU_ID}/${reportId}`).set(null);
    req.session.flash = { type: "ok", message: "report removed" };
    return res.redirect("/preferences");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to remove report" };
    return res.redirect("/preferences");
  }
});

app.post("/unblock", requireAuth, async (req, res) => {
  const me = res.locals.me;
  const userId = me ? String(me.id) : String(req.session.userId);
  const unblockId = (req.body.unblock_user_id || "").toString().trim();

  if (!unblockId) {
    req.session.flash = { type: "error", message: "nothing to unblock" };
    return res.redirect("/preferences");
  }

  try {
    await rtdb().ref(`blocks/${userId}/${String(unblockId)}`).set(null);
    req.session.flash = { type: "ok", message: "unblocked" };
    return res.redirect("/preferences");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to unblock" };
    return res.redirect("/preferences");
  }
});

app.post("/preferences", requireAuth, async (req, res) => {
  // simple filters. leaving stuff blank means "no preference"
  const minAgeRaw = (req.body.pref_min_age || "").toString().trim();
  const maxAgeRaw = (req.body.pref_max_age || "").toString().trim();
  const rankRaw = (req.body.pref_rank || "").toString().trim();
  const gendersRaw = req.body.pref_genders;

  const minAge = minAgeRaw ? parseInt(minAgeRaw, 10) : null;
  const maxAge = maxAgeRaw ? parseInt(maxAgeRaw, 10) : null;

  let rankMax = null;
  if (rankRaw && rankRaw !== "any") {
    const n = parseInt(rankRaw, 10);
    if (!Number.isFinite(n) || !RANK_PREF_THRESHOLDS.includes(n)) {
      req.session.flash = { type: "error", message: "pick a valid rank option" };
      return res.redirect("/preferences");
    }
    rankMax = n;
  }

  let genders = [];
  if (Array.isArray(gendersRaw)) genders = gendersRaw.map(x => String(x));
  else if (typeof gendersRaw === "string" && gendersRaw) genders = [gendersRaw];
  genders = genders.filter(g => GENDERS.includes(g));

  if (minAge !== null && (!Number.isFinite(minAge) || minAge < 18 || minAge > 120)) {
    req.session.flash = { type: "error", message: "min age has to be 18-120 (or leave blank)" };
    return res.redirect("/preferences");
  }
  if (maxAge !== null && (!Number.isFinite(maxAge) || maxAge < 18 || maxAge > 120)) {
    req.session.flash = { type: "error", message: "max age has to be 18-120 (or leave blank)" };
    return res.redirect("/preferences");
  }
  if (minAge !== null && maxAge !== null && minAge > maxAge) {
    req.session.flash = { type: "error", message: "min age cant be bigger than max age" };
    return res.redirect("/preferences");
  }

  const now = Date.now();
  const userId = String(req.session.userId);
  try {
    await rtdb().ref(`prefs/${userId}`).set({
      min_age: minAge,
      max_age: maxAge,
      genders,
      rank_max: rankMax,
      updated_at: now,
    });
    req.session.flash = { type: "ok", message: "preferences saved" };
    return res.redirect("/preferences");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to save preferences" };
    return res.redirect("/preferences");
  }
});

app.get("/profile", requireAuth, (req, res) => {
  res.render("pages/profile_view", { title: "profile" });
});

app.get("/profile/edit", requireAuth, (req, res) => {
  res.render("pages/profile", { title: "edit profile" });
});

app.post("/profile", requireAuth, async (req, res) => {
  const ageRaw = (req.body.age || "").toString().trim();
  const bioRaw = (req.body.bio || "").toString().trim();
  const genderRaw = (req.body.gender || "").toString().trim();
  const discordRaw = (req.body.discord || "").toString().trim();
  const displayNameRaw = (req.body.display_name || "").toString().trim();

  const age = parseInt(ageRaw, 10);
  const bio = bioRaw.slice(0, BIO_MAX);
  const gender = GENDERS.includes(genderRaw) ? genderRaw : null;
  const discord = discordRaw.slice(0, 64);
  const displayName = displayNameRaw.slice(0, 40);

  if (hasSlur(bioRaw) || hasSlur(discordRaw) || hasSlur(displayNameRaw)) {
    // auto-report and block saving
    try {
      await createAutoReport({
        me: res.locals.me,
        toUserId: String(req.session.userId),
        toUser: null,
        where: "profile",
        text: `profile text contained blocked slur`,
      });
    } catch (e) {
      console.error(e);
    }
    req.session.flash = { type: "error", message: "blocked word detected. profile not saved" };
    return res.redirect("/profile/edit");
  }

  if (!Number.isFinite(age)) {
    req.session.flash = { type: "error", message: "age has to be a number" };
    return res.redirect("/profile");
  }

  // 17 or under: instaban (persist in rtdb so they cant oauth back in)
  if (age <= 17) {
    if (!isAdmin(res.locals.me)) {
      try {
        await rtdb().ref(`osu_bans/${String(req.session.userId)}`).set({
          at: Date.now(),
          reason: "underage_age_field",
        });
      } catch (e) {
        console.error(e);
      }
      clearCookie(res, "admin_override");
      clearCookie(res, "admin_override_foid");
      return req.session.destroy(() => {
        res.redirect("/?banned=1");
      });
    }
    req.session.flash = {
      type: "error",
      message: "you gotta be 18+ to use this site. no exceptions",
    };
    return res.redirect("/profile");
  }

  if (!bio || bio.length < 5) {
    req.session.flash = {
      type: "error",
      message: "bio is too short. give ppl something to work with",
    };
    return res.redirect("/profile");
  }

  if (bioRaw.length > BIO_MAX) {
    req.session.flash = {
      type: "warn",
      message: `bio was too long so we cut it to ${BIO_MAX} chars`,
    };
  }

  if (!gender) {
    req.session.flash = {
      type: "error",
      message: "pick a gender option",
    };
    return res.redirect("/profile");
  }

  const now = Date.now();
  const userId = String(req.session.userId);
  try {
    await rtdb().ref(`profiles/${userId}`).set({
      age,
      bio,
      gender,
      discord: discord || null,
      display_name: displayName || null,
      updated_at: now,
    });
    req.session.flash = { type: "ok", message: "profile saved" };
    return res.redirect("/browse");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to save profile" };
    return res.redirect("/profile");
  }
});

async function cleanupLongBios() {
  const fdb = rtdb();
  const snap = await fdb.ref("profiles").get();
  const obj = snap.exists() ? snap.val() : {};

  const now = Date.now();
  const updates = {};
  let wiped = 0;

  for (const [userId, p] of Object.entries(obj || {})) {
    if (!p) continue;
    const bio = (p.bio || "").toString();
    if (bio && bio.length > BIO_MAX) {
      // wipe their bio if it's too long
      updates[`profiles/${userId}/bio`] = "";
      updates[`profiles/${userId}/updated_at`] = now;
      wiped += 1;
    }
  }

  if (Object.keys(updates).length) {
    await fdb.ref().update(updates);
  }

  return wiped;
}

app.post("/admin/cleanup-bios", async (req, res) => {
  try {
    const wiped = await cleanupLongBios();
    req.session.flash = { type: "ok", message: `cleaned ${wiped} bios` };
    return res.redirect("/preferences");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to clean bios" };
    return res.redirect("/preferences");
  }
});

app.post("/admin/wipe-user", async (req, res) => {
  const q = (req.body.q || "").toString().trim();
  if (!q) return res.redirect("/preferences");

  try {
    const fdb = rtdb();

    async function chunkedUpdate(updates, chunkSize) {
      const keys = Object.keys(updates || {});
      for (let i = 0; i < keys.length; i += chunkSize) {
        const chunk = {};
        for (const k of keys.slice(i, i + chunkSize)) chunk[k] = updates[k];
        await fdb.ref().update(chunk);
      }
    }

    const usersSnap = await fdb.ref("users").get();
    const usersObj = usersSnap.exists() ? usersSnap.val() : {};

    // find target id: either exact id, or username match (case-insensitive)
    let targetId = null;
    if (usersObj && usersObj[q]) {
      targetId = String(q);
    } else {
      const qLower = q.toLowerCase();
      for (const [id, u] of Object.entries(usersObj || {})) {
        if (!u || !u.username) continue;
        if (String(u.username).toLowerCase() === qLower) {
          targetId = String(id);
          break;
        }
      }
    }

    if (!targetId) {
      req.session.flash = { type: "error", message: "user not found" };
      return res.redirect("/preferences");
    }

    if (ADMIN_OSU_IDS.has(String(targetId))) {
      req.session.flash = { type: "error", message: "cant wipe an admin" };
      return res.redirect("/preferences");
    }

    const updates = {};
    updates[`users/${targetId}`] = null;
    updates[`profiles/${targetId}`] = null;
    updates[`prefs/${targetId}`] = null;
    updates[`blocks/${targetId}`] = null;
    updates[`inbox/${targetId}`] = null;
    updates[`wiped/${targetId}`] = true;

    // NOTE: we do NOT scan/delete messages in every inbox here anymore.
    // that gets huge and times out on bigger databases.
    // instead we "tombstone" them and hide them in the UI (wiped/{id}=true).
    let inboxDeletes = 0;

    // remove reports involving them
    const repSnap = await fdb.ref(`reports/${ADMIN_OSU_ID}`).get();
    const repObj = repSnap.exists() ? repSnap.val() : {};
    for (const [rid, r] of Object.entries(repObj || {})) {
      if (!r) continue;
      if (String(r.from_user_id || "") === String(targetId) || String(r.to_user_id || "") === String(targetId)) {
        updates[`reports/${ADMIN_OSU_ID}/${rid}`] = null;
      }
    }

    // do updates in batches so firebase doesnt choke on huge payloads
    await chunkedUpdate(updates, 400);

    req.session.flash = { type: "ok", message: `wiped user ${targetId}` };
    return res.redirect("/preferences");
  } catch (e) {
    console.error("wipe user failed", e);
    req.session.flash = { type: "error", message: "failed to wipe user" };
    return res.redirect("/preferences");
  }
});

app.get("/admin/messages", async (req, res) => {
  const rawQ = String(req.query.q || "").trim();
  if (!rawQ) {
    return res.render("pages/admin_message_search", {
      title: "admin · messages",
      keyword: "",
      matches: [],
      truncated: false,
      error: null,
    });
  }

  try {
    const { matches, truncated, error } = await adminSearchInboxMessages(rawQ);
    return res.render("pages/admin_message_search", {
      title: "admin · messages",
      keyword: rawQ,
      matches,
      truncated,
      error,
    });
  } catch (e) {
    console.error(e);
    return res.render("pages/admin_message_search", {
      title: "admin · messages",
      keyword: rawQ,
      matches: [],
      truncated: false,
      error: "search failed (check server logs)",
    });
  }
});

// full chat between two accounts — admins only (requireAdmin before any data load)
app.get("/admin/messages/thread", async (req, res) => {
  const a = String(req.query.a || "").trim();
  const b = String(req.query.b || "").trim();
  const returnQ = String(req.query.return_q || "").trim();

  if (!a || !b || a === b) {
    req.session.flash = { type: "error", message: "bad thread link" };
    return res.redirect("/admin/messages");
  }

  try {
    const fdb = rtdb();
    const [{ messages, error }, userSnapA, userSnapB] = await Promise.all([
      adminLoadThreadBetween(a, b),
      fdb.ref(`users/${a}`).get(),
      fdb.ref(`users/${b}`).get(),
    ]);

    if (error) {
      req.session.flash = { type: "error", message: error };
      return res.redirect("/admin/messages");
    }

    const ua = userSnapA.exists() ? userSnapA.val() : {};
    const ub = userSnapB.exists() ? userSnapB.val() : {};

    return res.render("pages/admin_inbox_thread", {
      title: "admin · chat",
      userA: a,
      userB: b,
      nameA: ua.username || `id ${a}`,
      nameB: ub.username || `id ${b}`,
      osuA: ua.osu_id || null,
      osuB: ub.osu_id || null,
      avatarA: ua.avatar_url || null,
      avatarB: ub.avatar_url || null,
      messages,
      return_q: returnQ,
    });
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to load thread" };
    return res.redirect("/admin/messages");
  }
});

app.get("/admin/view-profile", async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (!q) return res.redirect("/preferences");

  try {
    const fdb = rtdb();
    const usersSnap = await fdb.ref("users").get();
    const usersObj = usersSnap.exists() ? usersSnap.val() : {};

    let targetId = null;
    if (usersObj && usersObj[q]) {
      targetId = String(q);
    } else {
      const qLower = q.toLowerCase();
      for (const [id, u] of Object.entries(usersObj || {})) {
        if (!u || !u.username) continue;
        if (String(u.username).toLowerCase() === qLower) {
          targetId = String(id);
          break;
        }
      }
    }

    if (!targetId) {
      return res.render("pages/admin_view_profile", {
        title: "admin view",
        user: null,
        profile: null,
        prefs: null,
        cute_tint: false,
      });
    }

    const [profileSnap, prefsSnap] = await Promise.all([
      fdb.ref(`profiles/${targetId}`).get(),
      fdb.ref(`prefs/${targetId}`).get(),
    ]);

    const user = usersObj[targetId] || null;
    const profile = profileSnap.exists() ? profileSnap.val() : null;
    const prefs = prefsSnap.exists() ? prefsSnap.val() : null;

    const cute_tint = user ? userHasCuteTint(user.username, profile ? profile.display_name : null) : false;
    return res.render("pages/admin_view_profile", { title: "admin view", user, profile, prefs, cute_tint });
  } catch (e) {
    console.error(e);
    return res.render("pages/admin_view_profile", {
      title: "admin view",
      user: null,
      profile: null,
      prefs: null,
      cute_tint: false,
    });
  }
});

// all registered users — admin only (requireAdminSection)
app.get("/admin/users", async (req, res) => {
  const qRaw = String(req.query.q || "").trim();
  const qLower = qRaw.toLowerCase();

  try {
    const fdb = rtdb();
    const [usersSnap, profilesSnap, bansSnap] = await Promise.all([
      fdb.ref("users").get(),
      fdb.ref("profiles").get(),
      fdb.ref("osu_bans").get(),
    ]);

    const usersObj = usersSnap.exists() ? usersSnap.val() : {};
    const profilesObj = profilesSnap.exists() ? profilesSnap.val() : {};
    const bansObj = bansSnap.exists() ? bansSnap.val() : {};

    const allRows = [];
    for (const [id, u] of Object.entries(usersObj || {})) {
      if (!u) continue;
      const idStr = String(id);
      const p = profilesObj[idStr] || null;
      const osuIdStr = u.osu_id != null ? String(u.osu_id) : idStr;
      const username = u.username ? String(u.username) : "";
      const displayName = p && p.display_name ? String(p.display_name) : "";

      allRows.push({
        id: idStr,
        osu_id: osuIdStr,
        username,
        display_name: displayName || null,
        avatar_url: u.avatar_url || null,
        age: p && p.age != null ? p.age : null,
        gender: p && p.gender ? String(p.gender) : null,
        global_rank: u.global_rank != null && typeof u.global_rank === "number" ? u.global_rank : null,
        has_profile: !!p,
        banned_rtdb: !!(bansObj && bansObj[idStr]),
        banned_static: OSU_ID_BLACKLIST.has(idStr),
        is_staff: ADMIN_OSU_IDS.has(idStr),
      });
    }

    allRows.sort((a, b) => {
      const an = (a.username || a.id).toLowerCase();
      const bn = (b.username || b.id).toLowerCase();
      if (an < bn) return -1;
      if (an > bn) return 1;
      return a.id.localeCompare(b.id);
    });

    let rows = allRows;
    if (qLower) {
      rows = allRows.filter(r => {
        const hay = `${r.id} ${r.osu_id} ${r.username} ${r.display_name || ""}`.toLowerCase();
        return hay.includes(qLower);
      });
    }

    return res.render("pages/admin_user_list", {
      title: "admin · users",
      rows,
      q: qRaw,
      total_all: allRows.length,
      total_shown: rows.length,
    });
  } catch (e) {
    console.error(e);
    return res.render("pages/admin_user_list", {
      title: "admin · users",
      rows: [],
      q: qRaw,
      total_all: 0,
      total_shown: 0,
      load_error: "could not load users (check server logs)",
    });
  }
});

app.get("/browse", requireAuthOrGuest, async (req, res) => {
  const me = res.locals.me;
  const fdb = rtdb();
  const prefs = res.locals.prefs || null;
  // both site admins: no block/pref filter, no 50 cap — see everyone
  const isAllAccess = me && isAdmin(me);

  const [usersSnap, profilesSnap, allPrefsSnap] = await Promise.all([
    fdb.ref("users").get(),
    fdb.ref("profiles").get(),
    fdb.ref("prefs").get(),
  ]);

  const usersObj = usersSnap.exists() ? usersSnap.val() : {};
  const profilesObj = profilesSnap.exists() ? profilesSnap.val() : {};
  const prefsAll = allPrefsSnap.exists() ? allPrefsSnap.val() : {};

  const out = [];
  for (const [id, u] of Object.entries(usersObj || {})) {
    if (!u) continue;
    if (me && String(id) === String(me.id)) continue;
    const p = profilesObj ? profilesObj[id] : null;
    if (!p) continue;

    const rawPref = prefsAll[id] || null;
    const their_prefs = rawPref
      ? {
          min_age: rawPref.min_age != null ? rawPref.min_age : null,
          max_age: rawPref.max_age != null ? rawPref.max_age : null,
          genders: Array.isArray(rawPref.genders) ? rawPref.genders : [],
          rank_max: rawPref.rank_max != null && typeof rawPref.rank_max === "number" ? rawPref.rank_max : null,
        }
      : null;

    out.push({
      id,
      osu_id: u.osu_id,
      username: u.username,
      display_name: p.display_name || null,
      avatar_url: u.avatar_url || null,
      country_code: u.country_code || null,
      global_rank: u.global_rank || null,
      badge_count: typeof u.badge_count === "number" ? u.badge_count : null,
      age: p.age,
      bio: (p.bio || "").slice(0, BIO_MAX),
      gender: p.gender || null,
      updated_at: p.updated_at || 0,
      their_prefs,
      cute_tint: userHasCuteTint(u.username, p.display_name),
    });
  }

  // remove blocked users
  let baseList = out;
  if (me && !isAllAccess) {
    const blocksSnap = await fdb.ref(`blocks/${String(me.id)}`).get();
    const blocksObj = blocksSnap.exists() ? blocksSnap.val() : {};
    const blockedIds = new Set(Object.keys(blocksObj || {}));
    baseList = out.filter(u => !blockedIds.has(String(u.id)));
  }

  // apply your preferences if set
  let filtered = baseList;
  if (prefs && !isAllAccess) {
    filtered = baseList.filter(u => {
      if (!u) return false;
      if (!u.age || !u.gender) return false;
      if (prefs.min_age !== null && typeof prefs.min_age === "number" && u.age < prefs.min_age) return false;
      if (prefs.max_age !== null && typeof prefs.max_age === "number" && u.age > prefs.max_age) return false;
      if (Array.isArray(prefs.genders) && prefs.genders.length > 0) {
        if (!prefs.genders.includes(u.gender)) return false;
      }
      if (prefs.rank_max != null && typeof prefs.rank_max === "number") {
        const gr = u.global_rank;
        if (gr == null || gr > prefs.rank_max) return false;
      }
      return true;
    });
  }

  filtered = orderBrowseForDisplay(baseList, filtered);

  // normal users get 50. admins get everyone.
  const list = isAllAccess ? filtered : filtered.slice(0, 50);
  res.render("pages/browse", { title: "browse", users: list });
});

app.post("/account/destroy", requireAuth, async (req, res) => {
  try {
    const me = res.locals.me;
    const userId = me ? String(me.id) : String(req.session.userId);
    const fdb = rtdb();

    // delete own user + profile + inbox
    const updates = {};
    updates[`users/${userId}`] = null;
    updates[`profiles/${userId}`] = null;
    updates[`inbox/${userId}`] = null;

    // also delete messages you sent to other people (stored in their inbox)
    const inboxSnap = await fdb.ref("inbox").get();
    const inboxObj = inboxSnap.exists() ? inboxSnap.val() : {};

    for (const [toId, msgs] of Object.entries(inboxObj || {})) {
      if (!msgs) continue;
      for (const [msgId, msg] of Object.entries(msgs || {})) {
        if (!msg) continue;
        if (String(msg.from_user_id) === String(userId)) {
          updates[`inbox/${toId}/${msgId}`] = null;
        }
      }
    }

    await fdb.ref().update(updates);

    req.session.destroy(() => {
      // cant show flash after destroying session, so just bounce home
      res.redirect("/");
    });
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to destroy account" };
    res.redirect("/profile");
  }
});

app.post("/message/send", requireAuth, requireProfile, async (req, res) => {
  const me = res.locals.me;
  const toUserId = (req.body.to_user_id || "").toString().trim();
  const bodyRaw = (req.body.body || "").toString().trim();
  const body = bodyRaw.slice(0, 500);
  const redirectTo = (req.body.redirect_to || "").toString().trim();

  if (!toUserId) {
    req.session.flash = { type: "error", message: "invalid recipient" };
    return res.redirect("/browse");
  }

  if (String(toUserId) === String(me.id)) {
    req.session.flash = { type: "error", message: "u cant message urself" };
    return res.redirect("/browse");
  }

  if (!body || body.length < 1) {
    req.session.flash = { type: "error", message: "message is empty" };
    return res.redirect("/browse");
  }

  const fdb = rtdb();
  const toUserSnap = await fdb.ref(`users/${toUserId}`).get();
  if (!toUserSnap.exists()) {
    req.session.flash = { type: "error", message: "user not found" };
    return res.redirect("/browse");
  }

  if (hasSlur(bodyRaw)) {
    try {
      await createAutoReport({
        me,
        toUserId,
        toUser: toUserSnap.val(),
        where: "message",
        text: bodyRaw,
      });
    } catch (e) {
      console.error(e);
    }
    req.session.flash = { type: "error", message: "message blocked (slur)" };
    return res.redirect(redirectTo || "/browse");
  }

  // block checks
  const [iBlockSnap, theyBlockSnap] = await Promise.all([
    fdb.ref(`blocks/${String(me.id)}/${String(toUserId)}`).get(),
    fdb.ref(`blocks/${String(toUserId)}/${String(me.id)}`).get(),
  ]);
  if (iBlockSnap.exists()) {
    req.session.flash = { type: "error", message: "u blocked them" };
    return res.redirect(redirectTo || "/browse");
  }
  if (theyBlockSnap.exists()) {
    req.session.flash = { type: "error", message: "they blocked u" };
    return res.redirect(redirectTo || "/browse");
  }

  const now = Date.now();
  // store in their inbox (incoming)
  const msgRef = fdb.ref(`inbox/${toUserId}`).push();
  await msgRef.set({
    id: msgRef.key,
    direction: "in",
    from_user_id: String(me.id),
    from_username: me.username,
    from_osu_id: me.osu_id,
    from_avatar_url: me.avatar_url || null,
    to_user_id: String(toUserId),
    body,
    created_at: now,
    read_at: null,
  });

  // also store a copy in your inbox (outgoing) so u can see what u sent
  const toUser = toUserSnap.val() || {};
  const myCopyRef = fdb.ref(`inbox/${String(me.id)}`).push();
  await myCopyRef.set({
    id: myCopyRef.key,
    direction: "out",
    from_user_id: String(me.id),
    from_username: me.username,
    from_osu_id: me.osu_id,
    from_avatar_url: me.avatar_url || null,
    to_user_id: String(toUserId),
    to_username: toUser.username || "unknown",
    to_osu_id: toUser.osu_id || null,
    to_avatar_url: toUser.avatar_url || null,
    body,
    created_at: now,
    read_at: now, // dont count as unread for you
  });

  req.session.flash = { type: "ok", message: "message sent" };
  res.redirect(redirectTo || "/browse");
});

app.get("/inbox", requireAuth, requireProfile, async (req, res) => {
  const me = res.locals.me;
  const userId = String(me.id);
  const fdb = rtdb();

  const [snap, blocksSnap, wipedSnap] = await Promise.all([
    fdb.ref(`inbox/${userId}`).get(),
    fdb.ref(`blocks/${userId}`).get(),
    fdb.ref("wiped").get(),
  ]);

  const obj = snap.exists() ? snap.val() : {};
  const blocksObj = blocksSnap.exists() ? blocksSnap.val() : {};
  const blockedIds = new Set(Object.keys(blocksObj || {}));
  const wipedObj = wipedSnap.exists() ? wipedSnap.val() : {};
  const wipedIds = new Set(Object.keys(wipedObj || {}));

  const messages = Object.values(obj || {});

  // group into conversations by other user id
  const convoMap = {};
  for (const m of messages) {
    if (!m) continue;
    const dir = m.direction || (m.to_user_id ? "in" : "in");
    const otherId = dir === "out" ? String(m.to_user_id || "") : String(m.from_user_id || "");
    if (!otherId) continue;
    if (blockedIds.has(otherId)) continue;
    if (wipedIds.has(otherId)) continue;

    if (!convoMap[otherId]) {
      convoMap[otherId] = {
        otherId,
        name: dir === "out" ? (m.to_username || "unknown") : (m.from_username || "unknown"),
        avatar_url: dir === "out" ? (m.to_avatar_url || null) : (m.from_avatar_url || null),
        last_body: "",
        last_at: 0,
        unread: 0,
      };
    }

    const c = convoMap[otherId];
    const at = m.created_at || 0;
    if (at >= (c.last_at || 0)) {
      c.last_at = at;
      c.last_body = m.body || "";
      // keep name/avatar fresh too
      c.name = dir === "out" ? (m.to_username || c.name) : (m.from_username || c.name);
      c.avatar_url = dir === "out" ? (m.to_avatar_url || c.avatar_url) : (m.from_avatar_url || c.avatar_url);
    }

    // only count unread incoming for this convo
    if (dir !== "out" && !m.read_at) c.unread += 1;
  }

  const convos = Object.values(convoMap);
  convos.sort((a, b) => (b.last_at || 0) - (a.last_at || 0));

  res.render("pages/inbox", { title: "inbox", convos });
});

app.get("/inbox/:otherId", requireAuth, requireProfile, async (req, res) => {
  const me = res.locals.me;
  const userId = String(me.id);
  const otherId = String(req.params.otherId || "").trim();
  const viewRaw = String(req.query.view || "both");
  const view = ["both", "received", "sent"].includes(viewRaw) ? viewRaw : "both";
  const fdb = rtdb();

  // blocked?
  const blockSnap = await fdb.ref(`blocks/${userId}/${otherId}`).get();
  if (blockSnap.exists()) {
    req.session.flash = { type: "warn", message: "u blocked them" };
    return res.redirect("/inbox");
  }

  const wipedSnap = await fdb.ref(`wiped/${otherId}`).get();
  if (wipedSnap.exists()) {
    req.session.flash = { type: "warn", message: "user was wiped" };
    return res.redirect("/inbox");
  }

  const snap = await fdb.ref(`inbox/${userId}`).get();
  const obj = snap.exists() ? snap.val() : {};
  const all = Object.values(obj || {});

  // filter just this thread
  let thread = all.filter(m => {
    if (!m) return false;
    const dir = m.direction || (m.to_user_id ? "in" : "in");
    const oid = dir === "out" ? String(m.to_user_id || "") : String(m.from_user_id || "");
    return String(oid) === String(otherId);
  });

  // sort oldest -> newest like a chat
  thread.sort((a, b) => (a.created_at || 0) - (b.created_at || 0));

  // apply view filter
  if (view === "received") thread = thread.filter(m => (m.direction || "in") !== "out");
  if (view === "sent") thread = thread.filter(m => (m.direction || "in") === "out");

  // figure out other user info from any message we have
  let other = { name: "unknown", osu_id: null, avatar_url: null };
  for (const m of all) {
    if (!m) continue;
    if (String(m.from_user_id) === String(otherId)) {
      other = { name: m.from_username || "unknown", osu_id: m.from_osu_id || null, avatar_url: m.from_avatar_url || null };
      break;
    }
    if (String(m.to_user_id) === String(otherId)) {
      other = { name: m.to_username || "unknown", osu_id: m.to_osu_id || null, avatar_url: m.to_avatar_url || null };
    }
  }

  // mark unread incoming from them as read (only in this thread)
  const now = Date.now();
  const updates = {};
  for (const m of all) {
    if (!m || !m.id) continue;
    const dir = m.direction || "in";
    const oid = dir === "out" ? String(m.to_user_id || "") : String(m.from_user_id || "");
    if (dir !== "out" && String(oid) === String(otherId) && !m.read_at) {
      updates[`inbox/${userId}/${m.id}/read_at`] = now;
    }
  }
  // mark read is ok in read-only (not sending messages)
  if (Object.keys(updates).length) {
    await fdb.ref().update(updates);
  }

  res.render("pages/inbox_thread", { title: "inbox", me, otherId, other, messages: thread, view });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`server running on port ${PORT}`);
});

