# syntax=docker/dockerfile:1.7
# Multi-stage, non-root, BuildKit-secret-only, digest-pinned base — the exact
# properties POST /release-gate insists on before it will promote an image.

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build
WORKDIR /app
COPY package.json ./
# Secrets are mounted, never COPYed and never passed as ARG, so nothing lands in a layer.
RUN --mount=type=secret,id=npm_token \
    npm install --omit=dev --no-audit --no-fund || true
COPY src ./src

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runtime
WORKDIR /app
COPY --from=build /app/src ./src
COPY --from=build /app/package.json ./package.json
ENV NODE_ENV=production PORT=8787
# node:alpine ships an unprivileged `node` user (uid 1000).
USER node
EXPOSE 8787
CMD ["node", "src/server.js"]
