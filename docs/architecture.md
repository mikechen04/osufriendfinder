# Architecture

This doc explains the repo at a higher level so you do not need to reverse-engineer `server.js` every time.

## High-level setup

The project is mostly a traditional server-rendered Express app with some front-end JavaScript on top.

There are 2 rendering paths:

1. Express + EJS pages for authenticated app flows
2. A root landing page made from `index.html` + `app.js` + `styles.css`

The landing page is still aware of live app state because the server can inject banner HTML into it, and the browser can also fetch banner state from `/api/site-status` when needed.

## Main pieces

### `server.js`

This is the main entry point and contains:

- app setup
- session config
- auth middleware
- page routes
- feed / inbox / browse handlers
- admin routes
- landing page HTML injection

This repo intentionally keeps a lot of logic in one file. It is not split into controllers/services yet.

### `load-env.js`

Used for local development only.

- Reads `.env` with `dotenv.parse`
- avoids BOM weirdness
- does not override already-set env vars
- skips `.env` loading on Cloud Run so production env/secrets stay in control

### `firebase.js`

Bootstraps Firebase Admin and exposes:

- `rtdb()` for Realtime Database
- `firestore()` for Firestore

Credentials can come from:

- `FIREBASE_SERVICE_ACCOUNT_JSON`
- `FIREBASE_SERVICE_ACCOUNT_PATH`
- application default credentials on GCP

### `firestore-session-store.js`

Small custom `express-session` store used in production so sessions survive across multiple Cloud Run instances.

### `osu.js`

Small helper module for osu! OAuth:

- build authorize URL
- exchange code for token
- fetch `/me`

## Rendering model

### Server-rendered pages

Most signed-in pages are rendered through EJS under `views/pages/`.

Examples:

- browse
- profile
- preferences
- feed
- inbox
- admin screens

### Landing page

The landing page uses:

- `index.html`
- `styles.css`
- `app.js`

At runtime, `server.js` can inject:

- announcement banner
- read-only banner
- preview banner
- flash messages
- featured/showcase data

If the page is hosted statically, `app.js` can fetch `/api/site-status` and render announcement / read-only banners on the client.

## Session + auth flow

### User login

1. User hits `/auth/osu`
2. App redirects to osu! OAuth
3. osu! sends user back to `/auth/osu/callback`
4. App exchanges code for token
5. App fetches osu user info
6. App stores session + user info

### Session storage

- local dev: SQLite store
- Cloud Run multi-instance: Firestore store

That Firestore piece matters because in-memory sessions break easily once multiple Cloud Run instances are involved.

## Data model (rough)

Most state lives in Realtime Database. Based on route usage, important top-level areas include:

- `users`
- `profiles`
- `prefs`
- `inbox`
- `blocks`
- `reports`
- `site/announcement`
- feed-related nodes
- bans / blacklist-related nodes

This repo does not currently have a formal schema file, so the route handlers are the source of truth.

## Access levels

The app effectively has a few roles:

- public visitor
- guest user via gate code
- signed-in user
- admin/staff
- admin previewing as regular user

There is also a site-wide read-only mode that blocks normal write actions while still allowing staff to work.

## Custom domain / static domain behavior

One tricky part of this project is that a custom domain or static host may serve the landing page without going through Express.

Because of that:

- server-side injection alone is not enough
- the browser needs a fallback API for live status

That is why `/api/site-status` exists and why the client defaults to `window.location.origin` when fetching status.

## Things to be aware of before refactoring

- `server.js` is large and mixes routing with business logic
- a lot of page behavior depends on `res.locals`
- landing page behavior depends on string replacement / injection
- production behavior is sensitive to env config, especially Cloud Run vs local `.env`
- auth/session bugs can look like deployment bugs if the wrong store is used
