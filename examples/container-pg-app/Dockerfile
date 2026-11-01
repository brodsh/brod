# A container app with a managed Postgres database (request_database). Brod gives it DATABASE_URL, which reaches the
# database at brod-db.internal:5432 through the node. `migrate` in brod.json runs migrate.js before each new version
# serves.
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js migrate.js ./
CMD ["node", "server.js"]
