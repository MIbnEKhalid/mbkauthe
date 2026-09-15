# Production Deployment Guide for MBKAuthe v6

This guide covers production deployment best practices, HTTPS cookie configuration, reverse proxy setup, and cloud hosting.

---

## Production Deployment Checklist

- [ ] **Set `IS_DEPLOYED=true`**: Ensures session cookies are marked `Secure`, `HttpOnly`, and properly scoped across subdomains.
- [ ] **Generate Strong Cryptographic Secrets**: Ensure `MAIN_SECRET_TOKEN` and `SESSION_SECRET_KEY` are distinct 32-byte (64 hex character) random strings.
- [ ] **Database Connection Pooling**: When using PostgreSQL, configure `LOGIN_DB` with SSL (`sslmode=require`) and connection pool limits appropriate for your server capacity.
- [ ] **Trust Proxy**: If running behind a reverse proxy (Nginx, Cloudflare, AWS ALB, Caddy), enable `app.set('trust proxy', 1)`.
- [ ] **Graceful Shutdown**: Register `registerGracefulShutdown()` to ensure database connections and active transactions terminate cleanly during zero-downtime redeployments.

---

## Reverse Proxy (Nginx) Example

```nginx
server {
    listen 443 ssl http2;
    server_name auth.mbktech.org;

    ssl_certificate /etc/letsencrypt/live/mbktech.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mbktech.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## Serverless / Container Deployment (e.g. Docker, Vercel)

### Dockerfile

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src/ ./src/
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
EXPOSE 3000
CMD ["node", "dist/index.js"]
```
