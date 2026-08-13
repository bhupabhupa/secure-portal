# Secure Portal API
# Stage 1: install deps — needs build tools because better-sqlite3 is a
# native module (compiles if no prebuilt binary matches the platform/ABI).
FROM node:24-slim AS deps
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --omit=dev

# Stage 2: runtime — slim image, no toolchain
FROM node:24-slim
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "src/index.js"]
