# Example naive MCP server — INTENTIONALLY INSECURE (the control the gateway protects).
FROM node:20-slim
WORKDIR /app

# Install workspace deps for just this package (copied standalone for a small image).
COPY package.json ./
RUN npm install --omit=dev --no-package-lock \
 && npm install --no-save tsx

COPY tsconfig.json ./
COPY src ./src

EXPOSE 3015
CMD ["npx", "tsx", "src/index.ts"]
