FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY src ./src
COPY tsconfig.json ./
RUN npm run build && npm prune --omit=dev
FROM node:24-alpine
WORKDIR /app
COPY --from=build /app /app
USER node
# Default: the stdio MCP server. For the hosted connector (mcp.reach.dog) override the
# command, e.g. Cloud Run: --command=node --args=dist/http.js (listens on PORT, default 8080).
ENTRYPOINT ["node", "dist/server.js"]
