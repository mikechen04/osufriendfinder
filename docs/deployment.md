# Deployment

This repo is designed to run locally and on Google Cloud Run.

## Production shape

Typical production flow:

1. GitHub repo stores source
2. Cloud Build builds the Docker image
3. Image is pushed to Artifact Registry
4. Cloud Run deploys that image
5. Optional custom domain points at Cloud Run

## Local vs production env behavior

This repo has a local `.env` loader in `load-env.js`.

Important rule:

- local dev uses `.env`
- Cloud Run should use Cloud Run env vars / secrets

`load-env.js` now skips `.env` on Cloud Run so baked local values do not break production startup.

That matters for things like:

- `PORT=3000`
- Windows file paths in `FIREBASE_SERVICE_ACCOUNT_PATH`
- local OAuth callback URLs

## Required Cloud Run env vars

At minimum, set these in Cloud Run `Variables & secrets`:

- `OSU_CLIENT_ID`
- `OSU_CLIENT_SECRET`
- `OSU_REDIRECT_URI`
- `FIREBASE_DATABASE_URL`
- `SESSION_SECRET`
- `GUEST_CODE`

Depending on your Firebase auth setup, also set one of:

- `FIREBASE_SERVICE_ACCOUNT_JSON`
- or attach a service account that application default credentials can use

Optional but useful:

- `USE_FIRESTORE_SESSIONS=1`
- `FIRESTORE_SESSION_COLLECTION=express_sessions`
- `ADMIN_EMERGENCY_CODE`
- `ADMIN_EMERGENCY_CODE2`
- `SITE_READ_ONLY`

## Docker build

The app uses the repo `Dockerfile`.

Important details:

- base image: `node:20-bookworm-slim`
- installs build tools for native deps
- runs `npm ci --omit=dev`
- copies the whole repo
- starts with `node server.js`
- exposes `8080`

## Cloud Run requirements

### Port

The app must listen on `process.env.PORT`.

If Cloud Run says the container did not listen on `PORT=8080`, common causes are:

- app crashed during startup
- local `.env` overrode `PORT`
- missing production env vars

### Service account

If using Firebase from Cloud Run, make sure the runtime service account has the right permissions for:

- Realtime Database / Firebase Admin access
- Firestore if using Firestore sessions

### Sessions

For multi-instance Cloud Run, use Firestore-backed sessions. In-memory sessions are unreliable once multiple instances are involved.

## Cloud Build trigger setup

Use a Dockerfile-based trigger and push to a normal Artifact Registry repo.

Example image name:

```text
us-east1-docker.pkg.dev/$PROJECT_ID/circlefriendfinder/osudatingmeow:$SHORT_SHA
```

Good trigger checklist:

- GitHub repo connection is valid
- repo is linked in Cloud Build repositories
- build type is `Dockerfile`
- image name points to Artifact Registry, not `cloud-run-source-deploy`
- trigger points at the correct branch

## Artifact Registry

Create a Docker repository in the same region as the Cloud Run service if possible.

Example:

- region: `us-east1`
- repository: `circlefriendfinder`

Once a build succeeds, the built image should appear there. That exact image URL can be pasted into Cloud Run `Edit & deploy new revision`.

## Custom domain

Cloud Run supports domain mapping.

If using a custom domain like `circle.aheriez.cafe`:

1. add a Cloud Run domain mapping
2. add the DNS records Google asks for
3. update `OSU_REDIRECT_URI`
4. update any hardcoded absolute URLs

This repo was adjusted so the landing page now prefers relative links and current-origin API calls, which helps custom domains stay on their own host.

## Static landing notes

If you ever serve the landing page statically:

- you lose server-side banner injection
- you still need live announcement / read-only state

That is why `/api/site-status` exists.

The front end can call that endpoint and render:

- announcement banner
- read-only banner

## Troubleshooting

### Cloud Build cannot read commit

Usually means one of:

- GitHub repo connection is stale/broken
- repo rename was not re-linked
- trigger points at the wrong linked repo
- branch/commit is not present on GitHub

### Cloud Run deploys old code

Check:

- correct Cloud Build trigger
- correct branch
- correct GCP project selected
- newest revision actually deployed
- traffic assigned to newest working revision

### Cloud Run import failed for image

If the image path looks like `cloud-run-source-deploy/...`, switch to a normal Artifact Registry image instead.

### Custom domain bounces to `run.app`

Look for absolute links in:

- `index.html`
- front-end JS
- OAuth redirect settings

Relative links are safer when the site should stay on the custom host.
