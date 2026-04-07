require("./load-env");

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);

const { getDb } = require("./db");
const { osuAuthorizeUrl, osuExchangeCodeForToken, osuGetMe } = require("./osu");

const app = express();
const db = getDb();

// cloud run / reverse proxy — needed so cookies + req.ip work behind https
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const GENDERS = ["male", "female", "enby", "other"];

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.sqlite",
      dir: path.join(__dirname, "data"),
    }),
    // no need to set SESSION_SECRET in .env for local dev
    secret: process.env.SESSION_SECRET || "osu-edating-local-dev-session-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

// attach user info for templates
app.use((req, res, next) => {
  res.locals.me = null;
  if (req.session && req.session.userId) {
    const user = db
      .prepare(
        `
        SELECT u.*, p.age, p.bio, p.gender
        FROM users u
        LEFT JOIN profiles p ON p.user_id = u.id
        WHERE u.id = ?
      `
      )
      .get(req.session.userId);
    res.locals.me = user || null;
  }

  res.locals.flash = req.session.flash || null;
  req.session.flash = null;
  next();
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
    return res.redirect("/profile");
  }
  next();
}

app.get("/", (req, res) => {
  res.render("pages/index", {
    title: "find your osu soulmate",
  });
});

app.get("/index.html", (req, res) => {
  res.redirect(301, "/");
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

    // upsert user
    const now = new Date().toISOString();
    const existing = db
      .prepare("SELECT id FROM users WHERE osu_id = ?")
      .get(me.id);

    let userId = null;
    if (!existing) {
      const info = db
        .prepare(
          `
          INSERT INTO users (osu_id, username, avatar_url, country_code, created_at)
          VALUES (?, ?, ?, ?, ?)
        `
        )
        .run(me.id, me.username, me.avatar_url || null, me.country_code || null, now);
      userId = info.lastInsertRowid;
    } else {
      db.prepare(
        `
        UPDATE users
        SET username = ?, avatar_url = ?, country_code = ?
        WHERE osu_id = ?
      `
      ).run(me.username, me.avatar_url || null, me.country_code || null, me.id);
      userId = existing.id;
    }

    req.session.userId = userId;

    return res.redirect("/profile");
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

app.get("/profile", requireAuth, (req, res) => {
  res.render("pages/profile", { title: "profile" });
});

app.post("/profile", requireAuth, (req, res) => {
  const ageRaw = (req.body.age || "").toString().trim();
  const bioRaw = (req.body.bio || "").toString().trim();
  const genderRaw = (req.body.gender || "").toString().trim();

  const age = parseInt(ageRaw, 10);
  const bio = bioRaw.slice(0, 400);
  const gender = GENDERS.includes(genderRaw) ? genderRaw : null;

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

  const now = new Date().toISOString();
  db.prepare(
    `
    INSERT INTO profiles (user_id, age, bio, gender, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      age = excluded.age,
      bio = excluded.bio,
      gender = excluded.gender,
      updated_at = excluded.updated_at
  `
  ).run(req.session.userId, age, bio, gender, now);

  res.redirect("/browse");
});

app.get("/browse", requireAuth, requireProfile, (req, res) => {
  const me = res.locals.me;
  const users = db
    .prepare(
      `
      SELECT u.id, u.osu_id, u.username, u.avatar_url, u.country_code, p.age, p.bio, p.gender, p.updated_at
      FROM users u
      JOIN profiles p ON p.user_id = u.id
      WHERE u.id != ?
      ORDER BY p.updated_at DESC
      LIMIT 50
    `
    )
    .all(me.id);

  res.render("pages/browse", { title: "browse", users });
});

app.post("/message/send", requireAuth, requireProfile, (req, res) => {
  const me = res.locals.me;
  const toUserId = parseInt(req.body.to_user_id, 10);
  const bodyRaw = (req.body.body || "").toString().trim();
  const body = bodyRaw.slice(0, 600);

  if (!Number.isFinite(toUserId)) {
    req.session.flash = { type: "error", message: "invalid recipient" };
    return res.redirect("/browse");
  }

  if (toUserId === me.id) {
    req.session.flash = { type: "error", message: "u cant message urself" };
    return res.redirect("/browse");
  }

  if (!body || body.length < 1) {
    req.session.flash = { type: "error", message: "message is empty" };
    return res.redirect("/browse");
  }

  const exists = db.prepare("SELECT id FROM users WHERE id = ?").get(toUserId);
  if (!exists) {
    req.session.flash = { type: "error", message: "user not found" };
    return res.redirect("/browse");
  }

  const now = new Date().toISOString();
  db.prepare(
    `
    INSERT INTO messages (from_user_id, to_user_id, body, created_at)
    VALUES (?, ?, ?, ?)
  `
  ).run(me.id, toUserId, body, now);

  req.session.flash = { type: "ok", message: "sent. now we wait" };
  res.redirect("/browse");
});

app.get("/inbox", requireAuth, requireProfile, (req, res) => {
  const me = res.locals.me;

  const messages = db
    .prepare(
      `
      SELECT
        m.id,
        m.body,
        m.created_at,
        m.read_at,
        u.username AS from_username,
        u.avatar_url AS from_avatar_url,
        u.osu_id AS from_osu_id
      FROM messages m
      JOIN users u ON u.id = m.from_user_id
      WHERE m.to_user_id = ?
      ORDER BY m.created_at DESC
      LIMIT 100
    `
    )
    .all(me.id);

  // mark unread as read when visiting inbox. simple.
  const now = new Date().toISOString();
  db.prepare(
    `
    UPDATE messages
    SET read_at = ?
    WHERE to_user_id = ? AND read_at IS NULL
  `
  ).run(now, me.id);

  res.render("pages/inbox", { title: "inbox", messages });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`server running on port ${PORT}`);
});

