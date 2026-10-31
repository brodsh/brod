# A container app for Brod: a source folder with a Dockerfile at its top. Brod builds it on a node and runs it as a
# non-root user on a read-only file system. It listens on $PORT (3000 here, from brod.json).
FROM node:22-alpine
WORKDIR /app
COPY server.js version.txt ./
CMD ["node", "server.js"]
