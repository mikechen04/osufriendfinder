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

const app = express();

// cloud run / reverse proxy — needed so cookies + req.ip work behind https
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const GENDERS = ["male", "female", "enby", "other"];
// browse age prefs (inputs + validation)
const PREF_AGE_MIN = 18;
const PREF_AGE_MAX = 67;
// browse filter: must be this rank or better (lower osu global_rank number). null = any rank
const RANK_PREF_THRESHOLDS = [1, 100, 500, 1000, 5000, 10000, 50000];
const BIO_MAX = 750;
// tourney teammate finder options
const TOURNEY_MODS = ["nm", "hr", "hd", "dt"];
const TOURNEY_SKILLSETS = ["aim", "flow aim", "streams", "alt", "tech", "gimmick", "low ar", "stamina", "speed", "tapping", "dt alt", "antimod", "all rounder", "wokeness"];
const TOURNEY_RANK_RANGES = ["open", "1k-5k", "5k-10k", "10k-50k", "50k+"];
const FEED_CAPTION_MAX = 500;
const FEED_COMMENT_MAX = 400;
const ANNOUNCE_TEXT_MAX = 2000;
const ANNOUNCE_MIN_HOURS = 0.25;
const ANNOUNCE_MAX_HOURS = 24 * 30; // 30 days
const ADMIN_OSU_ID = "9632648"; // owner/admin inbox id for reports etc
const ADMIN_SECOND_OSU_ID = "12742221"; // second admin emergency login
const ADMIN_OSU_IDS = new Set(["9632648", "12742221"]);
const ADMIN_EMERGENCY_CODE = (process.env.ADMIN_EMERGENCY_CODE || "").toString().trim();
const ADMIN_EMERGENCY_CODE2 = (process.env.ADMIN_EMERGENCY_CODE2 || "").toString().trim();
// guest browse code — set in env, never hardcoded
const GUEST_CODE = (process.env.GUEST_CODE || "").toString().trim();

// whole-site freeze: see .env.example
function envTruthy(name) {
  const v = String(process.env[name] || "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}
const SITE_READ_ONLY = envTruthy("SITE_READ_ONLY");
if (SITE_READ_ONLY) {
  console.warn("[site] SITE_READ_ONLY on — logins ok; posting/saving blocked for non-staff");
}

// only allow same-origin relative paths for redirect_to to prevent open redirects
// valid: "/inbox/123", "/browse"   invalid: "//evil.com", "https://evil.com"
function safeRedirectPath(raw, fallback) {
  var s = (raw || "").toString().trim();
  // must start with / but not // (protocol-relative)
  if (s && s.startsWith("/") && !s.startsWith("//")) return s;
  return fallback || "/browse";
}

// simple in-memory rate limiter — tracks how many times a user did something in a window
// not perfect (resets on restart, no redis) but fine for light abuse prevention
const rateLimitStore = new Map();
function checkRateLimit(userId, action, maxPerWindow, windowMs) {
  var key = `${userId}:${action}`;
  var now = Date.now();
  var entry = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
  }
  entry.count++;
  rateLimitStore.set(key, entry);
  return entry.count > maxPerWindow;
}

// ip-based rate limit — used for unauthenticated sensitive endpoints
function checkIpRateLimit(req, action, maxPerWindow, windowMs) {
  var ip = req.ip || "unknown";
  return checkRateLimit(ip, action, maxPerWindow, windowMs);
}

// constant-time string compare to prevent timing attacks on secret codes
function timingSafeEqual(a, b) {
  try {
    var aBuf = Buffer.from(String(a));
    var bBuf = Buffer.from(String(b));
    // must be same length for timingSafeEqual — pad to same length first
    var len = Math.max(aBuf.length, bBuf.length);
    var aPad = Buffer.alloc(len);
    var bPad = Buffer.alloc(len);
    aBuf.copy(aPad);
    bBuf.copy(bPad);
    return crypto.timingSafeEqual(aPad, bPad) && aBuf.length === bBuf.length;
  } catch (e) {
    return false;
  }
}

async function isOsuIdBlacklisted(fdb, osuIdStr) {
  const id = String(osuIdStr || "").trim();
  if (!id) return false;

  try {
    const snap = await fdb.ref(`site/blacklist/${id}`).get();
    return snap.exists();
  } catch (e) {
    console.error(e);
    return false;
  }
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

function safeHttpUrl(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  try {
    const u = new URL(s);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return s;
  } catch (e) {
    return "";
  }
}

async function buildFeedList(fdb, me) {
  const [postsSnap, likesSnap, commentsSnap] = await Promise.all([
    fdb.ref("feed_posts").get(),
    fdb.ref("feed_likes").get(),
    fdb.ref("feed_comments").get(),
  ]);
  const raw = postsSnap.exists() ? postsSnap.val() : {};
  const likesRoot = likesSnap.exists() ? likesSnap.val() : {};
  const commentsRoot = commentsSnap.exists() ? commentsSnap.val() : {};

  let rows = Object.entries(raw || {}).map(([id, p]) => Object.assign({}, p, { id }));
  rows.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  rows = rows.slice(0, 80);

  const myId = me ? String(me.id) : null;

  return rows.map(post => {
    const likeObj = (likesRoot && likesRoot[post.id]) || {};
    const likeCount = likeObj && typeof likeObj === "object" ? Object.keys(likeObj).length : 0;
    const iLiked = !!(myId && likeObj && likeObj[myId]);

    const comObj = (commentsRoot && commentsRoot[post.id]) || {};
    let comments = Object.entries(comObj || {}).map(([cid, c]) => ({
      id: cid,
      user_id: c && c.user_id ? String(c.user_id) : "",
      username: (c && c.username) || "unknown",
      text: (c && c.text != null ? String(c.text) : "").slice(0, FEED_COMMENT_MAX),
      created_at: c && c.created_at ? c.created_at : 0,
    }));
    comments.sort((a, b) => (a.created_at || 0) - (b.created_at || 0));

    return Object.assign({}, post, {
      like_count: likeCount,
      i_liked: iLiked,
      comments,
    });
  });
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

// tourney pill options — on app.locals so every ejs template (and nested includes) sees them
app.locals.TOURNEY_MODS_LIST = TOURNEY_MODS;
app.locals.TOURNEY_SKILLSETS_LIST = TOURNEY_SKILLSETS;
app.locals.TOURNEY_RANK_RANGES_LIST = TOURNEY_RANK_RANGES;

app.use(express.urlencoded({ extended: true }));
// note: express.static is registered after all routes (see bottom) so paths like /feed are never shadowed

const SESSION_MAX_AGE_MS = parseInt(process.env.SESSION_MAX_AGE_MS || String(14 * 24 * 60 * 60 * 1000), 10);
const SESSION_MAX_AGE_SEC = Math.floor(SESSION_MAX_AGE_MS / 1000);

// refuse to start in production without a real secret — fallback dev key is not safe
if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
  console.error("[FATAL] SESSION_SECRET is not set in production. Set it in your environment and restart.");
  process.exit(1);
}

const sessionOptions = {
  secret: process.env.SESSION_SECRET || "osu-effriend-local-dev-session-key",
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
      if ((!req.session || !req.session.userId) && ADMIN_EMERGENCY_CODE2) {
        const tokenF = cookies.admin_override_foid || "";
        if (tokenF && isValidOwnerToken(ADMIN_EMERGENCY_CODE2, tokenF)) {
          if (req.session) req.session.userId = ADMIN_SECOND_OSU_ID;
        }
      }
    }

    res.locals.me = null;
    res.locals.inboxUnread = null;
    res.locals.prefs = null;
    res.locals.isStaff = false;
    res.locals.isAdmin = false;
    res.locals.viewAsRegularUser = false;
    res.locals.tSavedFilter = null;
    res.locals.tSavedProfile = null;
    // tourney options — on res.locals so parent ejs can pass into nested includes (nested locals often skip app.locals merge)
    res.locals.tourneyModsList = TOURNEY_MODS;
    res.locals.tourneySkillsetsList = TOURNEY_SKILLSETS;
    res.locals.tourneyRankRangesList = TOURNEY_RANK_RANGES;

    if (req.session && req.session.userId) {
      const userId = String(req.session.userId);
      const fdb = rtdb();

      // dynamic ban list in rtdb + static file blacklist + rtdb blacklist — kick session so they cant keep browsing
      const [banSnap, blacklistOk] = await Promise.all([
        fdb.ref(`osu_bans/${userId}`).get(),
        isOsuIdBlacklisted(fdb, userId),
      ]);
      if (banSnap.exists() || blacklistOk) {
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
          // if they never set tourney_bio yet, fall back to friend bio so old accounts still work
          tourney_bio: profile
            ? (profile.tourney_bio != null && String(profile.tourney_bio).trim() !== ""
                ? profile.tourney_bio
                : profile.bio)
            : null,
          gender: profile ? profile.gender : null,
          discord: profile ? profile.discord : null,
          display_name: profile ? profile.display_name : null,
          cute_tint: userHasCuteTint(user.username, profile ? profile.display_name : null),
        };
        res.locals.prefs = prefs;
        res.locals.isStaff = isAdmin(res.locals.me);
        res.locals.isAdmin =
          res.locals.isStaff && !(req.session && req.session.previewAsUser);
        res.locals.viewAsRegularUser = !!(
          req.session &&
          req.session.previewAsUser &&
          res.locals.isStaff
        );

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
    res.locals.isStaff = false;
    res.locals.isAdmin = false;
    res.locals.viewAsRegularUser = false;
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
  // staff can do anything (even while previewing as user in the ui)
  if (res.locals.isStaff) return next();

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

const adminRouter = express.Router();
adminRouter.use(requireAuth);
adminRouter.use(requireAdmin);

// admin routes live on adminRouter + app.use("/admin", adminRouter) — fixes GET /admin reliably

function requireAuthOrGuest(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.session && req.session.guestOk) return next();
  return res.redirect("/enter");
}

// scores feed is osu accounts only (not guest browse)
function requireSignedInForFeed(req, res, next) {
  if (!req.session || !req.session.userId) {
    req.session.flash = { type: "warn", message: "sign in with osu! to use the scores feed" };
    return res.redirect("/");
  }
  next();
}

function requireProfile(req, res, next) {
  const me = res.locals.me;
  if (!me) return res.redirect("/");
  if (!me.age || !me.bio || !me.tourney_bio || !me.gender) {
    req.session.flash = {
      type: "warn",
      message: "finish ur profile first (both bios + age + gender)",
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
// pull featured users from firebase — same logic as the api route but reusable
async function getFeaturedUsers(userId, adminSeeAll) {
  const fdb = rtdb();
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

  // shuffle so it's different each page load
  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = list[i];
    list[i] = list[j];
    list[j] = tmp;
  }

  return list.slice(0, 6);
}

async function sendHomeHtml(req, res) {
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
    const annExp = Number(ann.expires_at);
    annBlock = `<div class="site-announcement" role="status" data-announcement-expires="${Number.isFinite(annExp) ? annExp : ""}"><button type="button" class="site-announcement-close" aria-label="close announcement">&times;</button><div class="site-announcement-inner"><span class="site-announcement-label">announcement</span><p class="site-announcement-text">${escapeHtml(ann.text)}</p><span class="site-announcement-until">shows until ${escapeHtml(until)}</span></div></div>`;
  }
  html = html.replace("<!--ANNOUNCEMENT-->", annBlock);
  let roBlock = "";
  const showRoBanner =
    SITE_READ_ONLY &&
    !(res.locals.isStaff && !(req.session && req.session.previewAsUser));
  if (showRoBanner) {
    roBlock =
      '<div class="site-readonly-banner" role="status"><div class="site-readonly-inner">read-only mode - browsing is enabled but you can not send messages</div></div>';
  }
  html = html.replace("<!--READONLY-->", roBlock);
  let previewBlock = "";
  if (res.locals.viewAsRegularUser) {
    previewBlock =
      '<div class="site-preview-banner" role="region" aria-label="preview mode"><div class="site-preview-inner"><span>viewing as a default user</span><form action="/admin/preview-as-user/end" method="post" class="inline"><button class="btn btn-primary btn-tiny" type="submit">back to admin</button></form></div></div>';
  }
  html = html.replace("<!--PREVIEW-->", previewBlock);
  if (flash) {
    html = html.replace(
      "<!--FLASH-->",
      `<div class="flash ${flash.type}">${escapeHtml(flash.message)}</div>`
    );
  } else {
    html = html.replace("<!--FLASH-->", "");
  }

  // inject showcase data server-side so the client never needs to fetch it
  let showcaseScript = "";
  const userId = req.session && req.session.userId ? String(req.session.userId) : null;
  if (userId) {
    try {
      const me = res.locals.me;
      const adminSeeAll = me && isAdmin(me);
      const users = await getFeaturedUsers(userId, adminSeeAll);
      // safe to inject as json — no user-controlled html here
      showcaseScript = `<script>window.__SHOWCASE__=${JSON.stringify(users)};</script>`;
    } catch (e) {
      // firebase hiccup — showcase just won't show, no big deal
    }
  }
  html = html.replace("<!--SHOWCASE_DATA-->", showcaseScript);

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

    res.json({ users: list.slice(0, 6) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ users: [] });
  }
});

app.get("/", async (req, res) => {
  await sendHomeHtml(req, res);
});

app.get("/index.html", async (req, res) => {
  await sendHomeHtml(req, res);
});

app.get("/enter", (req, res) => {
  // already in? go browse
  if (req.session && (req.session.userId || req.session.guestOk)) return res.redirect("/browse");
  res.render("pages/enter", { title: "enter" });
});

app.get("/terms", (req, res) => {
  res.render("pages/terms", { title: "terms of service" });
});

app.get("/privacy", (req, res) => {
  res.render("pages/privacy", { title: "privacy policy" });
});

app.get("/disclaimer", (req, res) => {
  res.render("pages/disclaimer", { title: "disclaimer" });
});

// emergency owner login (bypasses osu oauth during traffic)
app.get("/emergency", (req, res) => {
  res.render("pages/emergency", { title: "emergency" });
});

app.post("/emergency-login", (req, res) => {
  // 5 attempts per 15 min per ip — brute force protection
  if (checkIpRateLimit(req, "emergency-login", 5, 15 * 60 * 1000)) {
    req.session.flash = { type: "error", message: "too many attempts, try later" };
    return res.redirect("/");
  }

  const code = (req.body.code || "").toString().trim();

  // always run the compare (even when code not set) to avoid timing leak
  const valid = ADMIN_EMERGENCY_CODE && timingSafeEqual(code, ADMIN_EMERGENCY_CODE);
  if (!valid) {
    req.session.flash = { type: "error", message: "invalid" };
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
  return res.redirect("/browse");
});

app.get("/emergency-foid", (req, res) => {
  res.render("pages/emergency_foid", { title: "emergency" });
});

app.post("/emergency-foid-login", (req, res) => {
  if (checkIpRateLimit(req, "emergency-foid-login", 5, 15 * 60 * 1000)) {
    req.session.flash = { type: "error", message: "too many attempts, try later" };
    return res.redirect("/");
  }

  const code = (req.body.code || "").toString().trim();

  const valid = ADMIN_EMERGENCY_CODE2 && timingSafeEqual(code, ADMIN_EMERGENCY_CODE2);
  if (!valid) {
    req.session.flash = { type: "error", message: "invalid" };
    return res.redirect("/emergency-foid");
  }

  clearCookie(res, "admin_override");
  if (req.session) req.session.userId = ADMIN_SECOND_OSU_ID;
  const token = makeOwnerToken(ADMIN_EMERGENCY_CODE2);
  setCookie(res, "admin_override_foid", token, {
    path: "/",
    maxAgeSeconds: 7 * 24 * 60 * 60,
    httpOnly: true,
    sameSite: "Lax",
    secure: true,
  });

  req.session.flash = { type: "ok", message: "admin login ok" };
  return res.redirect("/browse");
});

app.post("/enter", (req, res) => {
  // rate limit: 10 attempts per 15 min per ip
  if (checkIpRateLimit(req, "enter", 10, 15 * 60 * 1000)) {
    req.session.flash = { type: "error", message: "too many attempts, try later" };
    return res.redirect("/enter");
  }

  const code = (req.body.code || "").toString().trim();
  const valid = GUEST_CODE && timingSafeEqual(code, GUEST_CODE);
  if (valid) {
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
    const fdb = rtdb();
    const [banSnap, blacklistOk] = await Promise.all([
      fdb.ref(`osu_bans/${osuIdStr}`).get(),
      isOsuIdBlacklisted(fdb, osuIdStr),
    ]);
    if (banSnap.exists() || blacklistOk) {
      req.session.userId = null;
      req.session.flash = { type: "error", message: "u are blocked from using this site" };
      return res.redirect("/");
    }

    // store user in rtdb using osu id as the key (stable on cloud run)
    const userId = String(me.id);
    const now = Date.now();
    await fdb.ref(`users/${userId}`).update({
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

    return res.redirect("/browse");
  } catch (err) {
    console.error(err);
    const errText = err && err.message ? String(err.message) : String(err);
    let msg = "osu! login failed. too much traffic on the server just wait or try again";
    // token step uses id+secret — callback url being right doesnt fix invalid_client
    if (errText.includes("invalid_client") || errText.includes("Client authentication failed")) {
      msg =
        "osu oauth: client id or client secret wrong in .env (must match the same app on osu). callback url only affects the authorize screen";
    }
    req.session.flash = { type: "error", message: msg };
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
  const redirectTo = safeRedirectPath(req.body.redirect_to, "/browse");

  if (!me) return res.redirect("/");
  if (!blockUserId) {
    req.session.flash = { type: "error", message: "nothing to block" };
    return res.redirect(redirectTo);
  }
  if (String(blockUserId) === String(me.id)) {
    req.session.flash = { type: "error", message: "u cant block urself" };
    return res.redirect(redirectTo);
  }

  // basic abuse prevention — 20 blocks per hour per user
  if (checkRateLimit(String(me.id), "block", 20, 60 * 60 * 1000)) {
    req.session.flash = { type: "error", message: "slow down, too many blocks" };
    return res.redirect(redirectTo);
  }

  try {
    await rtdb().ref(`blocks/${String(me.id)}/${String(blockUserId)}`).set(true);
    req.session.flash = { type: "ok", message: "blocked" };
    return res.redirect(redirectTo);
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to block" };
    return res.redirect(redirectTo);
  }
});

app.post("/report", requireAuth, async (req, res) => {
  const me = res.locals.me;
  const toUserId = (req.body.to_user_id || "").toString().trim();
  const bodyRaw = (req.body.body || "").toString().trim();
  const body = bodyRaw.slice(0, 500);
  // track if this report came from the inbox so admins can pull up the chat log
  const fromInbox = req.body.from_inbox === "1";

  if (!me) return res.redirect("/");
  if (!toUserId) {
    req.session.flash = { type: "error", message: "invalid report target" };
    return res.redirect("/browse");
  }
  if (!body || body.length < 3) {
    req.session.flash = { type: "error", message: "report is too short" };
    return res.redirect("/browse");
  }

  // 5 reports per hour per user — prevents spam
  if (checkRateLimit(String(me.id), "report", 5, 60 * 60 * 1000)) {
    req.session.flash = { type: "error", message: "slow down, too many reports" };
    return res.redirect(fromInbox ? `/inbox/${toUserId}` : "/browse");
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
      from_inbox: fromInbox || false,
      created_at: now,
    });

    req.session.flash = { type: "ok", message: "report sent" };
    // if they reported from inbox, send them back there instead of browse
    return res.redirect(fromInbox ? `/inbox/${toUserId}` : "/browse");
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

    // load saved prefs so the form shows current values
    const [prefsSnap, tourneyFilterSnap] = await Promise.all([
      fdb.ref(`prefs/${userId}`).get(),
      fdb.ref(`tourney_filters/${userId}`).get(),
    ]);
    const prefsData = prefsSnap.exists() ? prefsSnap.val() : null;
    const tourneyFilterData = tourneyFilterSnap.exists() ? tourneyFilterSnap.val() : null;

    let prefs = null;
    if (prefsData) {
      prefs = {
        min_age: prefsData.min_age != null ? Number(prefsData.min_age) : null,
        max_age: prefsData.max_age != null ? Number(prefsData.max_age) : null,
        genders: Array.isArray(prefsData.genders) ? prefsData.genders : [],
        rank_max: prefsData.rank_max != null ? Number(prefsData.rank_max) : null,
      };
    }

    let tourneyFilterPrefs = null;
    if (tourneyFilterData) {
      tourneyFilterPrefs = {
        mods: Array.isArray(tourneyFilterData.mods) ? tourneyFilterData.mods : [],
        skillsets: Array.isArray(tourneyFilterData.skillsets) ? tourneyFilterData.skillsets : [],
        rank_ranges: Array.isArray(tourneyFilterData.rank_ranges) ? tourneyFilterData.rank_ranges : [],
      };
    }

    res.locals.tSavedFilter = tourneyFilterPrefs;
    res.render("pages/preferences", {
      title: "preferences",
      blockedUsers,
      prefs,
      isAdmin: !!res.locals.isAdmin,
    });
  } catch (e) {
    console.error(e);
    res.locals.tSavedFilter = null;
    res.render("pages/preferences", {
      title: "preferences",
      blockedUsers: [],
      prefs: null,
      isAdmin: !!res.locals.isAdmin,
    });
  }
});

// admin tools dashboard
adminRouter.get("/", (req, res) => {
  res.render("pages/admin", { title: "admin" });
});

adminRouter.get("/reports", async (req, res) => {
  try {
    const fdb = rtdb();
    const repSnap = await fdb.ref(`reports/${ADMIN_OSU_ID}`).get();
    const repObj = repSnap.exists() ? repSnap.val() : {};
    let reports = Object.values(repObj || {});
    reports.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    res.render("pages/admin_reports", { title: "reports", reports });
  } catch (e) {
    console.error(e);
    res.render("pages/admin_reports", { title: "reports", reports: [] });
  }
});

// show banned users list
adminRouter.get("/banned", async (req, res) => {
  try {
    const fdb = rtdb();
    // bans live in two places: osu_bans (underage auto-bans) and site/blacklist (wipe bans)
    const [osuBansSnap, blacklistSnap, usersSnap] = await Promise.all([
      fdb.ref("osu_bans").get(),
      fdb.ref("site/blacklist").get(),
      fdb.ref("users").get(),
    ]);
    const osuBansObj = osuBansSnap.exists() ? osuBansSnap.val() : {};
    const blacklistObj = blacklistSnap.exists() ? blacklistSnap.val() : {};
    const usersObj = usersSnap.exists() ? usersSnap.val() : {};

    // merge both ban sources into one map keyed by id
    const merged = {};
    for (const [id, data] of Object.entries(osuBansObj || {})) {
      if (!data) continue;
      merged[id] = { at: data.at || null, reason: data.reason || null };
    }
    for (const [id] of Object.entries(blacklistObj || {})) {
      if (!merged[id]) merged[id] = { at: null, reason: "wiped/banned by admin" };
    }

    const bans = [];
    for (const [id, data] of Object.entries(merged)) {
      const u = usersObj[id] || {};
      bans.push({
        id,
        osu_id: u.osu_id ? String(u.osu_id) : id,
        username: u.username || null,
        at: data.at,
        reason: data.reason,
      });
    }
    // newest bans first, nulls at the end
    bans.sort((a, b) => (b.at || 0) - (a.at || 0));

    res.render("pages/admin_banned", { title: "banned users", bans });
  } catch (e) {
    console.error(e);
    res.render("pages/admin_banned", { title: "banned users", bans: [] });
  }
});

// unban a user (remove from osu_bans)
adminRouter.post("/unban", async (req, res) => {
  const osuId = String(req.body.osu_id || "").trim();
  if (!osuId) {
    req.session.flash = { type: "error", message: "no user id given" };
    return res.redirect("/admin/banned");
  }
  try {
    await rtdb().ref(`osu_bans/${osuId}`).remove();
    req.session.flash = { type: "success", message: `unbanned ${osuId}` };
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "something went wrong" };
  }
  res.redirect("/admin/banned");
});

adminRouter.post("/announcement", async (req, res) => {
  const me = res.locals.me;
  const text = (req.body.announcement_text || "").toString().trim().slice(0, ANNOUNCE_TEXT_MAX);
  const hours = parseFloat(String(req.body.duration_hours || "").trim());

  if (!text) {
    req.session.flash = { type: "error", message: "write something or use clear announcement" };
    return res.redirect("/admin");
  }

  if (!Number.isFinite(hours) || hours < ANNOUNCE_MIN_HOURS || hours > ANNOUNCE_MAX_HOURS) {
    req.session.flash = {
      type: "error",
      message: `duration must be ${ANNOUNCE_MIN_HOURS}–${ANNOUNCE_MAX_HOURS} hours`,
    };
    return res.redirect("/admin");
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
  return res.redirect("/admin");
});

adminRouter.post("/announcement/clear", async (req, res) => {
  try {
    await rtdb().ref("site/announcement").set(null);
    req.session.flash = { type: "ok", message: "announcement cleared" };
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to clear" };
  }
  return res.redirect("/admin");
});

adminRouter.post("/reports/done", async (req, res) => {
  const reportId = (req.body.report_id || "").toString().trim();
  if (!reportId) return res.redirect("/admin");

  try {
    await rtdb().ref(`reports/${ADMIN_OSU_ID}/${reportId}`).set(null);
    req.session.flash = { type: "ok", message: "report removed" };
    return res.redirect("/admin");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to remove report" };
    return res.redirect("/admin");
  }
});

adminRouter.post("/reports/ban", async (req, res) => {
  const reportId = (req.body.report_id || "").toString().trim();
  const banUserId = (req.body.ban_user_id || "").toString().trim();
  const banOsuId = (req.body.ban_osu_id || "").toString().trim();

  // reports sometimes have internal user id, sometimes just osu id
  const targetId = banUserId || banOsuId;
  if (!targetId) {
    req.session.flash = { type: "error", message: "no user id to ban" };
    return res.redirect("/admin/reports");
  }

  if (ADMIN_OSU_IDS.has(String(targetId))) {
    req.session.flash = { type: "error", message: "cant ban an admin" };
    return res.redirect("/admin/reports");
  }

  try {
    const now = Date.now();
    const fdb = rtdb();

    // mark them banned (used by login + request middleware)
    await fdb.ref(`osu_bans/${String(targetId)}`).set({
      at: now,
      reason: "admin_report_ban",
    });

    // remove this report too so it doesnt sit there forever
    if (reportId) {
      await fdb.ref(`reports/${ADMIN_OSU_ID}/${reportId}`).set(null);
    }

    req.session.flash = { type: "ok", message: `banned ${targetId}` };
    return res.redirect("/admin/reports");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to ban user" };
    return res.redirect("/admin/reports");
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

  if (minAge !== null && (!Number.isFinite(minAge) || minAge < PREF_AGE_MIN || minAge > PREF_AGE_MAX)) {
    req.session.flash = {
      type: "error",
      message: `min age has to be ${PREF_AGE_MIN}-${PREF_AGE_MAX} (or leave blank)`,
    };
    return res.redirect("/preferences");
  }
  if (maxAge !== null && (!Number.isFinite(maxAge) || maxAge < PREF_AGE_MIN || maxAge > PREF_AGE_MAX)) {
    req.session.flash = {
      type: "error",
      message: `max age has to be ${PREF_AGE_MIN}-${PREF_AGE_MAX} (or leave blank)`,
    };
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

app.get("/profile", requireAuth, async (req, res) => {
  const mode = req.query.mode === "tourney" ? "tourney" : "friend";
  try {
    const userId = String(req.session.userId);
    const fdb = rtdb();
    const tSnap = await fdb.ref(`tourney_prefs/${userId}`).get();
    const rawTourney = tSnap.exists() ? tSnap.val() : null;
    let tourneyPrefs = null;
    if (rawTourney) {
      tourneyPrefs = {
        mods: Array.isArray(rawTourney.mods) ? rawTourney.mods : [],
        skillsets: Array.isArray(rawTourney.skillsets) ? rawTourney.skillsets : [],
        rank_ranges: Array.isArray(rawTourney.rank_ranges) ? rawTourney.rank_ranges : [],
      };
    }
    res.render("pages/profile_view", { title: "profile", mode, tourneyPrefs });
  } catch (e) {
    console.error(e);
    res.render("pages/profile_view", { title: "profile", mode, tourneyPrefs: null });
  }
});

app.get("/profile/tourney", requireAuth, async (req, res) => {
  try {
    const userId = String(req.session.userId);
    const fdb = rtdb();
    const tSnap = await fdb.ref(`tourney_prefs/${userId}`).get();
    const rawTourney = tSnap.exists() ? tSnap.val() : null;
    let tourneyPrefs = null;
    if (rawTourney) {
      tourneyPrefs = {
        mods: Array.isArray(rawTourney.mods) ? rawTourney.mods : [],
        skillsets: Array.isArray(rawTourney.skillsets) ? rawTourney.skillsets : [],
        rank_ranges: Array.isArray(rawTourney.rank_ranges) ? rawTourney.rank_ranges : [],
      };
    }
    res.render("pages/profile_view", { title: "profile", mode: "tourney", tourneyPrefs });
  } catch (e) {
    console.error(e);
    res.render("pages/profile_view", { title: "profile", mode: "tourney", tourneyPrefs: null });
  }
});

app.get("/profile/edit", requireAuth, async (req, res) => {
  try {
    const userId = String(req.session.userId);
    const fdb = rtdb();
    const tSnap = await fdb.ref(`tourney_prefs/${userId}`).get();
    const rawTourney = tSnap.exists() ? tSnap.val() : null;
    // same shape as /preferences so the shared partial checks work
    let tourneyPrefs = null;
    if (rawTourney) {
      tourneyPrefs = {
        mods: Array.isArray(rawTourney.mods) ? rawTourney.mods : [],
        skillsets: Array.isArray(rawTourney.skillsets) ? rawTourney.skillsets : [],
        rank_ranges: Array.isArray(rawTourney.rank_ranges) ? rawTourney.rank_ranges : [],
      };
    }
    res.locals.tSavedProfile = tourneyPrefs;
    res.render("pages/profile", { title: "edit profile" });
  } catch (e) {
    res.locals.tSavedProfile = null;
    res.render("pages/profile", { title: "edit profile" });
  }
});

app.post("/profile", requireAuth, async (req, res) => {
  const ageRaw = (req.body.age || "").toString().trim();
  const bioRaw = (req.body.bio || "").toString().trim();
  const tourneyBioRaw = (req.body.tourney_bio || "").toString().trim();
  const genderRaw = (req.body.gender || "").toString().trim();
  const discordRaw = (req.body.discord || "").toString().trim();
  const displayNameRaw = (req.body.display_name || "").toString().trim();

  const age = parseInt(ageRaw, 10);
  const bio = bioRaw.slice(0, BIO_MAX);
  const tourney_bio = tourneyBioRaw.slice(0, BIO_MAX);
  const gender = GENDERS.includes(genderRaw) ? genderRaw : null;
  const discord = discordRaw.slice(0, 64);
  const displayName = displayNameRaw.slice(0, 40);

  if (hasSlur(bioRaw) || hasSlur(tourneyBioRaw) || hasSlur(discordRaw) || hasSlur(displayNameRaw)) {
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
      message: "friend finder bio is too short. give ppl something to work with",
    };
    return res.redirect("/profile");
  }

  if (!tourney_bio || tourney_bio.length < 5) {
    req.session.flash = {
      type: "error",
      message: "tourney teammate bio is too short too",
    };
    return res.redirect("/profile");
  }

  if (bioRaw.length > BIO_MAX) {
    req.session.flash = {
      type: "warn",
      message: `bio was too long so we cut it to ${BIO_MAX} chars`,
    };
  }

  if (tourneyBioRaw.length > BIO_MAX) {
    req.session.flash = {
      type: "warn",
      message: `tourney bio was too long so we cut it to ${BIO_MAX} chars`,
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
      tourney_bio,
      gender,
      discord: discord || null,
      display_name: displayName || null,
      updated_at: now,
    });
    req.session.flash = { type: "ok", message: "profile saved" };
    return res.redirect("/profile");
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
    const tb = (p.tourney_bio || "").toString();
    if (bio && bio.length > BIO_MAX) {
      updates[`profiles/${userId}/bio`] = "";
      updates[`profiles/${userId}/updated_at`] = now;
      wiped += 1;
    }
    if (tb && tb.length > BIO_MAX) {
      updates[`profiles/${userId}/tourney_bio`] = "";
      updates[`profiles/${userId}/updated_at`] = now;
      wiped += 1;
    }
  }

  if (Object.keys(updates).length) {
    await fdb.ref().update(updates);
  }

  return wiped;
}

adminRouter.post("/cleanup-bios", async (req, res) => {
  try {
    const wiped = await cleanupLongBios();
    req.session.flash = { type: "ok", message: `cleaned ${wiped} bios` };
    return res.redirect("/admin");
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "failed to clean bios" };
    return res.redirect("/admin");
  }
});

adminRouter.post("/wipe-user", async (req, res) => {
  const q = (req.body.q || "").toString().trim();
  if (!q) return res.redirect("/admin");

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
      return res.redirect("/admin");
    }

    if (ADMIN_OSU_IDS.has(String(targetId))) {
      req.session.flash = { type: "error", message: "cant wipe an admin" };
      return res.redirect("/admin");
    }

    const updates = {};
    updates[`users/${targetId}`] = null;
    updates[`profiles/${targetId}`] = null;
    updates[`prefs/${targetId}`] = null;
    updates[`blocks/${targetId}`] = null;
    updates[`inbox/${targetId}`] = null;
    updates[`wiped/${targetId}`] = true;
    // ban too so they cant just log back in again
    updates[`site/blacklist/${targetId}`] = true;

    // NOTE: we do NOT scan/delete messages in every inbox here anymore.
    // that gets huge and times out on bigger databases.
    // instead we "tombstone" them and hide them in the UI (wiped/{id}=true).

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
    return res.redirect("/admin");
  } catch (e) {
    console.error("wipe user failed", e);
    req.session.flash = { type: "error", message: "failed to wipe user" };
    return res.redirect("/admin");
  }
});

adminRouter.get("/messages", async (req, res) => {
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
adminRouter.get("/messages/thread", async (req, res) => {
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

adminRouter.get("/view-profile", async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (!q) return res.redirect("/admin");

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
        adminViewUserId: null,
        convoRows: [],
        recentMessages: [],
      });
    }

    const [profileSnap, prefsSnap, inboxSnap] = await Promise.all([
      fdb.ref(`profiles/${targetId}`).get(),
      fdb.ref(`prefs/${targetId}`).get(),
      fdb.ref(`inbox/${targetId}`).get(),
    ]);

    const user = usersObj[targetId] || null;
    const profile = profileSnap.exists() ? profileSnap.val() : null;
    const prefs = prefsSnap.exists() ? prefsSnap.val() : null;
    const inboxObj = inboxSnap.exists() ? inboxSnap.val() : {};
    const allMessages = Object.values(inboxObj || {}).filter(Boolean);

    const convoMap = {};
    for (const m of allMessages) {
      const dir = m.direction === "out" ? "out" : "in";
      const otherId = dir === "out" ? String(m.to_user_id || "") : String(m.from_user_id || "");
      if (!otherId) continue;

      const otherUser = usersObj[otherId] || null;
      const nameFromMsg = dir === "out" ? (m.to_username || "") : (m.from_username || "");
      const avatarFromMsg = dir === "out" ? (m.to_avatar_url || null) : (m.from_avatar_url || null);

      if (!convoMap[otherId]) {
        convoMap[otherId] = {
          other_id: otherId,
          name: nameFromMsg || (otherUser && otherUser.username ? otherUser.username : `id ${otherId}`),
          avatar_url: avatarFromMsg || (otherUser && otherUser.avatar_url ? otherUser.avatar_url : null),
          last_body: "",
          last_at: 0,
          unread: 0,
          total: 0,
        };
      }

      const c = convoMap[otherId];
      const at = Number(m.created_at || 0);
      c.total += 1;
      if (dir !== "out" && !m.read_at) c.unread += 1;

      if (at >= (c.last_at || 0)) {
        c.last_at = at;
        c.last_body = (m.body || "").toString();
        c.name = nameFromMsg || c.name;
        c.avatar_url = avatarFromMsg || c.avatar_url;
      }
    }

    const convoRows = Object.values(convoMap).sort((a, b) => (b.last_at || 0) - (a.last_at || 0));

    const recentMessages = allMessages
      .map(m => {
        const dir = m.direction === "out" ? "out" : "in";
        const otherId = dir === "out" ? String(m.to_user_id || "") : String(m.from_user_id || "");
        const otherUser = usersObj[otherId] || null;
        const nameFromMsg = dir === "out" ? (m.to_username || "") : (m.from_username || "");
        // pick correct avatar: for incoming the sender is the other person, for outgoing the sender is the viewed user
        const otherAvatarFromMsg = dir === "out" ? (m.to_avatar_url || null) : (m.from_avatar_url || null);
        const otherAvatar = otherAvatarFromMsg || (otherUser && otherUser.avatar_url ? otherUser.avatar_url : null);
        return {
          id: String(m.id || ""),
          dir,
          other_id: otherId,
          other_name: nameFromMsg || (otherUser && otherUser.username ? otherUser.username : (otherId ? `id ${otherId}` : "unknown")),
          other_avatar_url: otherAvatar,
          body: (m.body || "").toString(),
          created_at: Number(m.created_at || 0),
          read_at: m.read_at || null,
        };
      })
      .sort((a, b) => (b.created_at || 0) - (a.created_at || 0))
      .slice(0, 80);

    const cute_tint = user ? userHasCuteTint(user.username, profile ? profile.display_name : null) : false;
    return res.render("pages/admin_view_profile", {
      title: "admin view",
      user,
      profile,
      prefs,
      cute_tint,
      adminViewUserId: targetId,
      convoRows,
      recentMessages,
    });
  } catch (e) {
    console.error(e);
    return res.render("pages/admin_view_profile", {
      title: "admin view",
      user: null,
      profile: null,
      prefs: null,
      cute_tint: false,
      adminViewUserId: null,
      convoRows: [],
      recentMessages: [],
    });
  }
});

// all registered users — admin only
adminRouter.get("/users", async (req, res) => {
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
        banned_static: false,
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

adminRouter.post("/preview-as-user", (req, res) => {
  req.session.previewAsUser = true;
  req.session.flash = {
    type: "info",
    message: "viewing as a default user — use the bar at the top to go back",
  };
  return res.redirect("/browse");
});

adminRouter.post("/preview-as-user/end", (req, res) => {
  req.session.previewAsUser = false;
  req.session.flash = { type: "ok", message: "back to admin view" };
  return res.redirect("/admin");
});

app.use("/admin", adminRouter);

app.post("/tourney-preferences", requireAuth, async (req, res) => {
  const userId = String(req.session.userId);
  const fdb = rtdb();
  const kind = req.body.tourney_kind === "filter" ? "filter" : "profile";

  // parse arrays from form — express gives string if one selected, array if multiple
  function toArr(raw, allowed) {
    var vals = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    return vals.map(v => String(v)).filter(v => allowed.includes(v));
  }

  const mods = toArr(req.body.tourney_mods, TOURNEY_MODS);
  const skillsets = toArr(req.body.tourney_skillsets, TOURNEY_SKILLSETS);
  const rank_ranges = toArr(req.body.tourney_rank_ranges, TOURNEY_RANK_RANGES);

  try {
    const savePath = kind === "filter" ? `tourney_filters/${userId}` : `tourney_prefs/${userId}`;
    await fdb.ref(savePath).set({ mods, skillsets, rank_ranges, updated_at: Date.now() });
    req.session.flash = {
      type: "ok",
      message: kind === "filter" ? "tourney browse filters saved" : "tourney profile setup saved",
    };
  } catch (e) {
    console.error(e);
    req.session.flash = {
      type: "error",
      message: kind === "filter" ? "failed to save tourney browse filters" : "failed to save tourney profile setup",
    };
  }
  var back = safeRedirectPath(req.body.tourney_redirect, "/preferences");
  res.redirect(back);
});

app.get("/browse", requireAuthOrGuest, async (req, res) => {
  const me = res.locals.me;
  const fdb = rtdb();
  const prefs = res.locals.prefs || null;
  const isAllAccess = me && isAdmin(me);
  const mode = req.query.mode === "tourney" ? "tourney" : "friend";
  let myTourneyFilters = null;

  if (me) {
    try {
      const myFilterSnap = await fdb.ref(`tourney_filters/${String(me.id)}`).get();
      const rawMine = myFilterSnap.exists() ? myFilterSnap.val() : null;
      if (rawMine) {
        myTourneyFilters = {
          mods: Array.isArray(rawMine.mods) ? rawMine.mods : [],
          skillsets: Array.isArray(rawMine.skillsets) ? rawMine.skillsets : [],
          rank_ranges: Array.isArray(rawMine.rank_ranges) ? rawMine.rank_ranges : [],
        };
      }
    } catch (e) {
      console.error(e);
    }
  }

  const [usersSnap, profilesSnap, allPrefsSnap, allTourneyPrefsSnap] = await Promise.all([
    fdb.ref("users").get(),
    fdb.ref("profiles").get(),
    fdb.ref("prefs").get(),
    fdb.ref("tourney_prefs").get(),
  ]);

  const usersObj = usersSnap.exists() ? usersSnap.val() : {};
  const profilesObj = profilesSnap.exists() ? profilesSnap.val() : {};
  const prefsAll = allPrefsSnap.exists() ? allPrefsSnap.val() : {};
  const tourneyPrefsAll = allTourneyPrefsSnap.exists() ? allTourneyPrefsSnap.val() : {};

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

    const rawTourney = tourneyPrefsAll[id] || null;
    const tourney_prefs = rawTourney
      ? {
          mods: Array.isArray(rawTourney.mods) ? rawTourney.mods : [],
          skillsets: Array.isArray(rawTourney.skillsets) ? rawTourney.skillsets : [],
          rank_ranges: Array.isArray(rawTourney.rank_ranges) ? rawTourney.rank_ranges : [],
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
      tourney_bio: (p.tourney_bio != null && String(p.tourney_bio).trim() !== ""
        ? p.tourney_bio
        : p.bio || ""
      ).slice(0, BIO_MAX),
      discord: p.discord || null,
      gender: p.gender || null,
      updated_at: p.updated_at || 0,
      their_prefs,
      tourney_prefs,
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

  let filtered = baseList;

  if (mode === "tourney") {
    // tourney mode: only show people who have at least one tourney pref set
    filtered = baseList.filter(u => {
      const tp = u.tourney_prefs;
      if (!tp) return false;
      return (tp.mods && tp.mods.length > 0) || (tp.skillsets && tp.skillsets.length > 0) || (tp.rank_ranges && tp.rank_ranges.length > 0);
    });

    // if viewer set tourney filters, only show profiles that match them
    if (myTourneyFilters && !isAllAccess) {
      const myMods = Array.isArray(myTourneyFilters.mods) ? myTourneyFilters.mods : [];
      const mySkills = Array.isArray(myTourneyFilters.skillsets) ? myTourneyFilters.skillsets : [];
      const myRanks = Array.isArray(myTourneyFilters.rank_ranges) ? myTourneyFilters.rank_ranges : [];
      const overlap = function(a, b) {
        if (!Array.isArray(a) || !Array.isArray(b) || !a.length || !b.length) return false;
        return a.some(v => b.includes(v));
      };

      filtered = filtered.filter(u => {
        const tp = u.tourney_prefs || { mods: [], skillsets: [], rank_ranges: [] };
        if (myMods.length && !overlap(tp.mods || [], myMods)) return false;
        if (mySkills.length && !overlap(tp.skillsets || [], mySkills)) return false;
        if (myRanks.length && !overlap(tp.rank_ranges || [], myRanks)) return false;
        return true;
      });
    }
  } else {
    // friend mode: apply the usual preference filters
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
  }

  const list = isAllAccess ? filtered : filtered.slice(0, 50);
  res.render("pages/browse", { title: "browse", users: list, mode });
});

app.get("/feed", requireSignedInForFeed, async (req, res) => {
  try {
    const fdb = rtdb();
    const posts = await buildFeedList(fdb, res.locals.me);
    return res.render("pages/feed", { title: "scores feed", posts });
  } catch (e) {
    console.error(e);
    req.session.flash = { type: "error", message: "could not load feed" };
    return res.render("pages/feed", { title: "scores feed", posts: [] });
  }
});

// dev helper: confirm the running server has latest tourney lists
if (process.env.NODE_ENV !== "production") {
  app.get("/debug/tourney-skillsets", (req, res) => {
    res.type("json").send({
      mods: TOURNEY_MODS,
      skillsets: TOURNEY_SKILLSETS,
      rank_ranges: TOURNEY_RANK_RANGES,
    });
  });
}

app.post("/feed/create", requireAuth, async (req, res) => {
  const me = res.locals.me;
  if (!me) return res.redirect("/feed");

  const imageUrl = safeHttpUrl(req.body.image_url);
  const replayUrl = safeHttpUrl(req.body.replay_url);
  const caption = (req.body.caption || "").toString().trim().slice(0, FEED_CAPTION_MAX);

  if (!imageUrl && !replayUrl) {
    req.session.flash = { type: "error", message: "need at least an image url or a replay url" };
    return res.redirect("/feed");
  }
  if (hasSlur(caption)) {
    req.session.flash = { type: "error", message: "caption blocked" };
    return res.redirect("/feed");
  }

  const fdb = rtdb();
  const postRef = fdb.ref("feed_posts").push();
  const now = Date.now();
  await postRef.set({
    author_id: String(me.id),
    author_username: me.username || "unknown",
    author_avatar_url: me.avatar_url || null,
    image_url: imageUrl || null,
    replay_url: replayUrl || null,
    caption: caption || null,
    created_at: now,
  });
  req.session.flash = { type: "ok", message: "posted" };
  return res.redirect("/feed");
});

app.post("/feed/like", requireAuth, async (req, res) => {
  const me = res.locals.me;
  if (!me) return res.redirect("/feed");
  const postId = (req.body.post_id || "").toString().trim();
  if (!postId) return res.redirect("/feed");

  const fdb = rtdb();
  const postSnap = await fdb.ref(`feed_posts/${postId}`).get();
  if (!postSnap.exists()) {
    req.session.flash = { type: "error", message: "post not found" };
    return res.redirect("/feed");
  }

  const uid = String(me.id);
  const likeRef = fdb.ref(`feed_likes/${postId}/${uid}`);
  const existing = await likeRef.get();
  if (existing.exists()) {
    await likeRef.remove();
  } else {
    await likeRef.set(true);
  }
  return res.redirect("/feed");
});

app.post("/feed/comment", requireAuth, async (req, res) => {
  const me = res.locals.me;
  if (!me) return res.redirect("/feed");
  const postId = (req.body.post_id || "").toString().trim();
  const bodyRaw = (req.body.body || "").toString().trim().slice(0, FEED_COMMENT_MAX);
  if (!postId || !bodyRaw) {
    req.session.flash = { type: "error", message: "empty comment" };
    return res.redirect("/feed");
  }
  if (hasSlur(bodyRaw)) {
    req.session.flash = { type: "error", message: "comment blocked" };
    return res.redirect("/feed");
  }

  const fdb = rtdb();
  const postSnap = await fdb.ref(`feed_posts/${postId}`).get();
  if (!postSnap.exists()) {
    req.session.flash = { type: "error", message: "post not found" };
    return res.redirect("/feed");
  }

  const cref = fdb.ref(`feed_comments/${postId}`).push();
  await cref.set({
    user_id: String(me.id),
    username: me.username || "unknown",
    text: bodyRaw,
    created_at: Date.now(),
  });
  return res.redirect("/feed");
});

app.post("/feed/delete", requireAuth, async (req, res) => {
  const me = res.locals.me;
  if (!me) return res.redirect("/feed");
  const postId = (req.body.post_id || "").toString().trim();
  if (!postId) return res.redirect("/feed");

  const fdb = rtdb();
  const postSnap = await fdb.ref(`feed_posts/${postId}`).get();
  if (!postSnap.exists()) {
    req.session.flash = { type: "error", message: "post not found" };
    return res.redirect("/feed");
  }
  const p = postSnap.val();
  const can =
    String(p.author_id || "") === String(me.id) || isAdmin(res.locals.me);
  if (!can) {
    req.session.flash = { type: "error", message: "cant delete that" };
    return res.redirect("/feed");
  }

  const updates = {};
  updates[`feed_posts/${postId}`] = null;
  updates[`feed_likes/${postId}`] = null;
  updates[`feed_comments/${postId}`] = null;
  await fdb.ref().update(updates);
  req.session.flash = { type: "ok", message: "deleted" };
  return res.redirect("/feed");
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
  const redirectTo = safeRedirectPath(req.body.redirect_to, "/browse");

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

// home page assets live next to index.html (styles.css + app.js) — explicit routes so deploy always finds them
app.get("/styles.css", (req, res) => {
  res.type("text/css");
  res.sendFile(path.join(__dirname, "styles.css"));
});
app.get("/app.js", (req, res) => {
  res.type("application/javascript");
  res.sendFile(path.join(__dirname, "app.js"));
});

// optional extra static files (empty by default)
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`server running on port ${PORT}`);
});

