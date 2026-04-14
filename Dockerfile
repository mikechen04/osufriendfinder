FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# index.html lives at repo root next to this Dockerfile (home page for GET /)

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "server.js"]
