# MCP Agent Gateway — runs under tsx (no build step).
FROM node:20-slim
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-package-lock \
 && npm install --no-save tsx

COPY tsconfig.json ./
COPY src ./src
COPY config ./config

EXPOSE 3014
CMD ["npx", "tsx", "src/index.ts"]
