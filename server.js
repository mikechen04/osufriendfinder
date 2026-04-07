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

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const sessionOptions = {
  // no need to set SESSION_SECRET in .env for local dev
  secret: process.env.SESSION_SECRET || "osu-edating-local-dev-session-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
  },
};

// cloud run containers can be picky about writing files in the image dir.
// keep it simple: use in-memory sessions in production for now.
if (process.env.NODE_ENV !== "production" && SQLiteStore) {
  sessionOptions.store = new SQLiteStore({
    db: "sessions.sqlite",
    dir: path.join(__dirname, "data"),
  });
}

app.use(session(sessionOptions));

// attach user info for templates
app.use(async (req, res, next) => {
  try {
    res.locals.me = null;
    res.locals.inboxUnread = null;
    res.locals.prefs = null;

    if (req.session && req.session.userId) {
      const userId = String(req.session.userId);
      const fdb = rtdb();

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
          age: profile ? profile.age : null,
          bio: profile ? profile.bio : null,
          gender: profile ? profile.gender : null,
          discord: profile ? profile.discord : null,
          display_name: profile ? profile.display_name : null,
        };
        res.locals.prefs = prefs;

        // count unread messages
        let unread = 0;
        for (const m of Object.values(inboxObj || {})) {
          if (m && !m.read_at) unread += 1;
        }
        res.locals.inboxUnread = unread;
      }
    }

    res.locals.flash = req.session.flash || null;
    req.session.flash = null;
    next();
  } catch (e) {
    console.error(e);
    res.locals.me = null;
    res.locals.flash = null;
    next();
  }
});

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect("/");
  }
  next();
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
  const flash = res.locals.flash;
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

app.get("/", (req, res) => {
  sendHomeHtml(req, res);
});

app.get("/index.html", (req, res) => {
  sendHomeHtml(req, res);
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

    // block blacklisted osu ids (ex: minors)
    if (OSU_ID_BLACKLIST.has(String(me.id))) {
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
      updated_at: now,
      created_at: now,
    });

    req.session.userId = userId;

    return res.redirect("/preferences");
  } catch (err) {
    console.error(err);
    req.session.flash = {
      type: "error",
      message: "osu! login failed. check your .env values + redirect url",
    };
    return res.redirect("/");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/preferences", requireAuth, (req, res) => {
  res.render("pages/preferences", { title: "preferences" });
});

app.post("/preferences", requireAuth, async (req, res) => {
  // simple filters. leaving stuff blank means "no preference"
  const minAgeRaw = (req.body.pref_min_age || "").toString().trim();
  const maxAgeRaw = (req.body.pref_max_age || "").toString().trim();
  const gendersRaw = req.body.pref_genders;

  const minAge = minAgeRaw ? parseInt(minAgeRaw, 10) : null;
  const maxAge = maxAgeRaw ? parseInt(maxAgeRaw, 10) : null;

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
  const bio = bioRaw.slice(0, 400);
  const gender = GENDERS.includes(genderRaw) ? genderRaw : null;
  const discord = discordRaw.slice(0, 64);
  const displayName = displayNameRaw.slice(0, 40);

  if (!Number.isFinite(age)) {
    req.session.flash = { type: "error", message: "age has to be a number" };
    return res.redirect("/profile");
  }

  if (age < 18) {
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

app.get("/browse", requireAuth, async (req, res) => {
  const me = res.locals.me;
  const fdb = rtdb();
  const prefs = res.locals.prefs || null;

  const [usersSnap, profilesSnap] = await Promise.all([
    fdb.ref("users").get(),
    fdb.ref("profiles").get(),
  ]);

  const usersObj = usersSnap.exists() ? usersSnap.val() : {};
  const profilesObj = profilesSnap.exists() ? profilesSnap.val() : {};

  const out = [];
  for (const [id, u] of Object.entries(usersObj || {})) {
    if (!u) continue;
    if (String(id) === String(me.id)) continue;
    const p = profilesObj ? profilesObj[id] : null;
    if (!p) continue;

    out.push({
      id,
      osu_id: u.osu_id,
      username: u.username,
      avatar_url: u.avatar_url || null,
      country_code: u.country_code || null,
      age: p.age,
      bio: p.bio,
      gender: p.gender || null,
      updated_at: p.updated_at || 0,
    });
  }

  // apply your preferences if set
  let filtered = out;
  if (prefs) {
    filtered = out.filter(u => {
      if (!u) return false;
      if (!u.age || !u.gender) return false;
      if (prefs.min_age !== null && typeof prefs.min_age === "number" && u.age < prefs.min_age) return false;
      if (prefs.max_age !== null && typeof prefs.max_age === "number" && u.age > prefs.max_age) return false;
      if (Array.isArray(prefs.genders) && prefs.genders.length > 0) {
        if (!prefs.genders.includes(u.gender)) return false;
      }
      return true;
    });
  }

  filtered.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  res.render("pages/browse", { title: "browse", users: filtered.slice(0, 50) });
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
  const body = bodyRaw.slice(0, 600);
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

  const snap = await fdb.ref(`inbox/${userId}`).get();
  const obj = snap.exists() ? snap.val() : {};

  const messages = Object.values(obj || {});
  messages.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));

  // mark unread as read
  const now = Date.now();
  const updates = {};
  for (const m of messages) {
    if (m && !m.read_at && m.id) {
      updates[`inbox/${userId}/${m.id}/read_at`] = now;
    }
  }
  if (Object.keys(updates).length) {
    await fdb.ref().update(updates);
  }

  res.render("pages/inbox", { title: "inbox", messages: messages.slice(0, 50) });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`server running on port ${PORT}`);
});

