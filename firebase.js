// firebase admin init for realtime database
// keep it basic: env var points to a service account json file or json string
// FIREBASE_DISABLED=1 skips live firebase (nuked / offline archive) so the server still serves pages

const fs = require("fs");
const admin = require("firebase-admin");

const FIREBASE_DISABLED =
  String(process.env.FIREBASE_DISABLED || process.env.FIREBASE_OFFLINE || "")
    .trim() === "1";

function mustEnv(name) {
  const raw = process.env[name];
  const v = raw == null ? "" : String(raw).trim();
  if (!v) throw new Error(`missing env var: ${name}`);
  return v;
}

function emptySnap() {
  return {
    exists() {
      return false;
    },
    val() {
      return null;
    },
  };
}

function offlineRef() {
  const ref = {
    get: async () => emptySnap(),
    set: async () => null,
    update: async () => null,
    remove: async () => null,
    push() {
      return {
        key: "offline",
        set: async () => null,
        update: async () => null,
      };
    },
    child() {
      return offlineRef();
    },
  };
  return ref;
}

function offlineRtdb() {
  return {
    ref() {
      return offlineRef();
    },
  };
}

function offlineFirestore() {
  const collection = {
    doc() {
      return {
        async get() {
          return { exists: false, data: () => null };
        },
        async set() {
          return null;
        },
        async delete() {
          return null;
        },
      };
    },
  };
  return {
    collection() {
      return collection;
    },
  };
}

function initFirebase() {
  if (FIREBASE_DISABLED) return;
  if (admin.apps.length) return;

  const databaseURL = mustEnv("FIREBASE_DATABASE_URL");

  const jsonRaw = (process.env.FIREBASE_SERVICE_ACCOUNT_JSON || "").trim();
  const jsonPath = (process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "").trim();

  let credential = null;

  if (jsonRaw) {
    credential = admin.credential.cert(JSON.parse(jsonRaw));
  } else if (jsonPath) {
    const file = fs.readFileSync(jsonPath, "utf8");
    credential = admin.credential.cert(JSON.parse(file));
  } else {
    // works on gcp if the runtime has a service account attached
    credential = admin.credential.applicationDefault();
  }

  admin.initializeApp({
    credential,
    databaseURL,
  });
}

function rtdb() {
  if (FIREBASE_DISABLED) return offlineRtdb();
  initFirebase();
  return admin.database();
}

// for shared express-session across cloud run instances (same service account as rtdb)
function firestore() {
  if (FIREBASE_DISABLED) return offlineFirestore();
  initFirebase();
  return admin.firestore();
}

module.exports = { rtdb, firestore, FIREBASE_DISABLED };
