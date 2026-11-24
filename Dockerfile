# syntax=docker/dockerfile:1

FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build \
 && rm -rf dist/test \
 && npm prune --omit=dev

FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
ARG GIT_SHA=""
ENV NODE_ENV=production \
    DATA_DIR=/data \
    BUILD_SHA=$GIT_SHA
LABEL org.opencontainers.image.revision=$GIT_SHA
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY public ./public
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "dist/healthcheck.js"]
CMD ["node", "dist/index.js"]
