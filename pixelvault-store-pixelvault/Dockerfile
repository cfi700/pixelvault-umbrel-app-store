FROM node:20-alpine

# Build deps for sharp (image processing) - needed on ARM and x86
RUN apk add --no-cache \
    vips-dev \
    python3 \
    make \
    g++ \
    libc6-compat

WORKDIR /app

# Copy and install dependencies first (better layer caching)
COPY app/backend/package*.json ./app/backend/
RUN cd app/backend && \
    npm install --production && \
    npm rebuild sharp --platform=linux --arch=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') || \
    npm install --production

# Copy application source
COPY app/backend/ ./app/backend/
COPY app/frontend/ ./app/frontend/

# Runtime config
ENV PORT=3000
ENV DATA_DIR=/data
ENV NODE_ENV=production

EXPOSE 3000

WORKDIR /app/app/backend
CMD ["node", "server.js"]
