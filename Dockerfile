FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=4175
WORKDIR /app
COPY --chown=node:node package.json server.mjs index.html styles.css app.js data.js engine.js ./
COPY --chown=node:node backend ./backend
USER node
EXPOSE 4175
CMD ["node", "server.mjs"]
