// read .env with fs + dotenv.parse — more reliable than dotenv.config() alone (bom, onedrive, etc.)
const path = require("path");
const fs = require("fs");
const dotenv = require("dotenv");

const envPath = path.join(__dirname, ".env");

function loadEnvFile() {
  if (!fs.existsSync(envPath)) {
    console.warn(`[env] no .env file at ${envPath}`);
    return;
  }
  let raw = fs.readFileSync(envPath, "utf8");
  // strip utf-8 bom if present (windows editors sometimes add it)
  if (raw.charCodeAt(0) === 0xfeff) {
    raw = raw.slice(1);
  }
  const parsed = dotenv.parse(raw);
  for (const [key, value] of Object.entries(parsed)) {
    // dont clobber real env vars (cloud run sets PORT=8080, secrets, etc.)
    // .env is mainly for local dev
    if (process.env[key] == null || String(process.env[key]).trim() === "") {
      process.env[key] = value;
    }
  }
}

loadEnvFile();
