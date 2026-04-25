FROM node:20-alpine

# Install build dependencies for sharp (image processing)
RUN apk add --no-cache vips-dev python3 make g++

WORKDIR /app

# Install backend dependencies first (layer caching)
COPY app/backend/package*.json ./app/backend/
RUN cd app/backend && npm install --production --no-optional

# Copy application code
COPY app/backend/ ./app/backend/
COPY app/frontend/ ./app/frontend/

# Data directory (mounted as volume by Umbrel)
VOLUME ["/data"]

ENV PORT=3000
ENV DATA_DIR=/data
ENV NODE_ENV=production

EXPOSE 3000

WORKDIR /app/app/backend
CMD ["node", "server.js"]
