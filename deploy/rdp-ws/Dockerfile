FROM node:22-bookworm-slim

WORKDIR /app

COPY deploy/rdp-ws/package.json deploy/rdp-ws/package-lock.json ./

RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

COPY deploy/rdp-ws/server.js ./server.js

ENV NODE_ENV=production

EXPOSE 8080

CMD ["node", "server.js"]
