# ────────────────────────────────────────────────────────────────────
# Multi-Cloud IPAM Scanner — Frontend (React + Vite)
# Multi-stage build: build static assets, then serve via nginx.
# ────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Install dependencies first to leverage Docker layer caching.
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

# Copy source and build the Vite production bundle.
COPY . .
RUN npm run build

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM nginx:alpine AS runner

# Replace the default nginx config with the SPA-aware one.
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy the built static assets into the nginx document root.
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose HTTP and HTTPS.
EXPOSE 80 443

# nginx images ship with a STSIGNAL handler that gracefully stops nginx.
CMD ["nginx", "-g", "daemon off;"]
