// tiny express-session store backed by cloud firestore — works across many cloud run instances
const session = require("express-session");
const { Timestamp } = require("firebase-admin/firestore");

class FirestoreSessionStore extends session.Store {
  constructor(db, options) {
    super();
    this.coll = db.collection((options && options.collection) || "express_sessions");
    this.ttlMs = ((options && options.ttlSeconds) || 14 * 24 * 60 * 60) * 1000;
  }

  get(sid, callback) {
    this.coll
      .doc(sid)
      .get()
      .then((snap) => {
        if (!snap.exists) return callback(null, null);
        const row = snap.data();
        const exp = row && row.expires_at;
        const expMs = exp && typeof exp.toMillis === "function" ? exp.toMillis() : 0;
        if (expMs && expMs < Date.now()) {
          return snap.ref
            .delete()
            .then(() => callback(null, null))
            .catch(() => callback(null, null));
        }
        let sess = null;
        try {
          sess = row.json ? JSON.parse(row.json) : null;
        } catch (e) {
          return callback(null, null);
        }
        callback(null, sess);
      })
      .catch((err) => callback(err));
  }

  set(sid, sess, callback) {
    let json;
    try {
      json = JSON.stringify(sess);
    } catch (err) {
      return callback(err);
    }
    const expiresAt = new Date(Date.now() + this.ttlMs);
    this.coll
      .doc(sid)
      .set({
        json,
        expires_at: Timestamp.fromDate(expiresAt),
      })
      .then(() => callback(null))
      .catch((err) => callback(err));
  }

  destroy(sid, callback) {
    this.coll
      .doc(sid)
      .delete()
      .then(() => callback(null))
      .catch((err) => callback(err));
  }

  touch(sid, sess, callback) {
    this.set(sid, sess, callback);
  }
}

module.exports = FirestoreSessionStore;
