# node slim + build tools — better-sqlite3 needs native compile (common cloud build failure without this)
FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# db.js is gitignored locally; cloud build only has db.example.js
RUN cp -f db.example.js db.js

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "server.js"]
