# circle! e-friend finder

A full-stack social web app for osu! players.

Users can sign in with osu!, browse profiles, message each other, post to a small feed, report users, and manage profile/preferences data. The app also has an admin surface for announcements, moderation, user search, and maintenance mode.

## Stack

| piece | notes |
| --- | --- |
| runtime | Node.js |
| server | Express |
| templating | EJS |
| auth | osu! OAuth 2.0 |
| primary data | Firebase Realtime Database |
| session storage | SQLite locally, Firestore on Cloud Run |
| deploy | Docker + Google Cloud Run |
| static landing support | root `index.html` + `app.js` + `styles.css` |

## Main features

- osu! OAuth login
- guest access via shared code
- profile creation and editing
- regular profile view and tourney profile view
- browse mode with filtering
- direct messages / inbox threads
- small social feed with likes and comments
- blocking and reporting
- admin announcement banner
- site-wide read-only / maintenance mode
- admin tools for bans, reports, user search, preview-as-user, and cleanup

## Repo layout

| path | what it does |
| --- | --- |
| `server.js` | main Express app, routes, middleware, page rendering, RTDB reads/writes |
| `index.html` | landing page shell used at `/` |
| `app.js` | front-end behavior for landing page, browse UI, banners, and other client interactions |
| `styles.css` | shared styling for landing page and rendered pages |
| `osu.js` | osu! OAuth helpers |
| `firebase.js` | Firebase Admin bootstrap for RTDB / Firestore |
| `firestore-session-store.js` | custom session store for Cloud Run multi-instance sessions |
| `load-env.js` | local `.env` loader with Cloud Run-safe behavior |
| `views/pages/` | EJS page templates |
| `views/partials/` | shared EJS partials |
| `Dockerfile` | production container build |

## How it works

### App flow

- The server renders most logged-in pages with EJS.
- The landing page uses root-level static assets: `index.html`, `styles.css`, and `app.js`.
- `server.js` injects banners, flash messages, and showcase data into the landing page when the request goes through Express.
- For static hosting cases, `app.js` can fetch `/api/site-status` and hydrate announcement / read-only banners on the client.

### Data flow

This app stores most app data in Firebase Realtime Database, including:

- users
- profiles
- prefs
- inbox
- reports
- blocks
- site announcement data
- feed data

### Sessions

- Local development can use SQLite-backed sessions.
- Production on Cloud Run can use Firestore-backed sessions so OAuth sessions still work across multiple instances.

## Routes at a glance

### Public / auth

- `GET /`
- `GET /enter`
- `POST /enter`
- `GET /auth/osu`
- `GET /auth/osu/callback`
- `POST /logout`
- `POST /guest/exit`

### API

- `GET /api/me`
- `GET /api/site-status`
- `GET /api/featured`

### User features

- `GET /browse`
- `GET /preferences`
- `POST /preferences`
- `POST /tourney-preferences`
- `GET /profile`
- `GET /profile/tourney`
- `GET /profile/edit`
- `POST /profile`
- `GET /feed`
- `POST /feed/create`
- `POST /feed/like`
- `POST /feed/comment`
- `POST /feed/delete`
- `GET /inbox`
- `GET /inbox/:otherId`
- `POST /message/send`
- `POST /block`
- `POST /unblock`
- `POST /report`
- `POST /account/destroy`

### Admin

- `GET /admin`
- `GET /admin/reports`
- `GET /admin/banned`
- `GET /admin/messages`
- `GET /admin/messages/thread`
- `GET /admin/view-profile`
- `GET /admin/users`
- `POST /admin/announcement`
- `POST /admin/announcement/clear`
- `POST /admin/unban`
- `POST /admin/reports/done`
- `POST /admin/reports/ban`
- `POST /admin/cleanup-bios`
- `POST /admin/wipe-user`
- `POST /admin/preview-as-user`
- `POST /admin/preview-as-user/end`

## Local development

### Requirements

- Node.js 20+ recommended
- npm
- Firebase project / RTDB
- osu! OAuth app credentials

### Setup

1. Install deps:

```bash
npm install
```

2. Copy envs:

```bash
cp .env.example .env
```

3. Fill in at least:

- `OSU_CLIENT_ID`
- `OSU_CLIENT_SECRET`
- `OSU_REDIRECT_URI`
- `FIREBASE_DATABASE_URL`
- `FIREBASE_SERVICE_ACCOUNT_PATH` for local dev
- `SESSION_SECRET`
- `GUEST_CODE`

4. Start the app:

```bash
npm run dev
```

5. Open:

```text
http://localhost:3000
```

## Environment variables

See `.env.example` for the full list. The important ones are:

| env | purpose |
| --- | --- |
| `PORT` | local dev port; Cloud Run provides its own `PORT` |
| `OSU_CLIENT_ID` | osu! OAuth client id |
| `OSU_CLIENT_SECRET` | osu! OAuth client secret |
| `OSU_REDIRECT_URI` | callback URL used by osu! OAuth |
| `FIREBASE_DATABASE_URL` | RTDB URL |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | local path to Firebase admin JSON |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | production-friendly JSON credential option |
| `USE_FIRESTORE_SESSIONS` | enables Firestore session store |
| `FIRESTORE_SESSION_COLLECTION` | optional Firestore collection name |
| `SESSION_SECRET` | required for production sessions |
| `GUEST_CODE` | guest gate code |
| `ADMIN_EMERGENCY_CODE` | owner emergency login |
| `ADMIN_EMERGENCY_CODE2` | second admin emergency login |
| `SITE_READ_ONLY` | write lock for maintenance mode |

## Deployment notes

### Docker / Cloud Run

- The app listens on `process.env.PORT`, which is required for Cloud Run.
- `load-env.js` skips loading local `.env` on Cloud Run so local Windows paths and `PORT=3000` do not break the container.
- Production secrets should be configured in Cloud Run `Variables & secrets`, not relied on from a baked `.env`.

### Cloud Build / Artifact Registry

- Build the container with the included `Dockerfile`.
- Push the image to Artifact Registry.
- Deploy that image to Cloud Run.
- If using a Cloud Build trigger, make sure it points at the current GitHub repo connection and pushes to a normal Artifact Registry repo.

### Static landing + custom domain

- The landing page can be served statically, but it still needs live app state for banners.
- `GET /api/site-status` exists so the client can fetch current announcement and read-only state.
- `app.js` defaults to `window.location.origin` for this, which helps custom domains like `circle.aheriez.cafe` stay on their own host instead of bouncing to `*.run.app`.

## Common gotchas

- If Cloud Run says the container did not listen on `PORT=8080`, check startup logs first. A crash during boot can look like a port issue.
- Do not rely on a local `.env` file inside production containers.
- If Cloud Build says it cannot read a commit, check the GitHub connection / linked repository in Cloud Build.
- If a custom domain keeps redirecting back to `run.app`, look for hardcoded absolute URLs in `index.html` or front-end code.

## Extra docs

- `docs/architecture.md`
- `docs/deployment.md`

## Disclaimer

Independent fan project. Not affiliated with ppy Pty Ltd or osu!.
