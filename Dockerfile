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
ENTRYPOINT ["node", "dist/server.js"]
