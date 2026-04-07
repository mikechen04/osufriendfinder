// firebase admin init for realtime database
// keep it basic: env var points to a service account json file or json string

const fs = require("fs");
const admin = require("firebase-admin");

function mustEnv(name) {
  const raw = process.env[name];
  const v = raw == null ? "" : String(raw).trim();
  if (!v) throw new Error(`missing env var: ${name}`);
  return v;
}

function initFirebase() {
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
  initFirebase();
  return admin.database();
}

// for shared express-session across cloud run instances (same service account as rtdb)
function firestore() {
  initFirebase();
  return admin.firestore();
}

module.exports = { rtdb, firestore };

