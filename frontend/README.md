# IPAM Multi-Cloud Security Platform — Frontend

The web interface for the IPAM Multi-Cloud Security Platform. A React 19 single-page application that provides JWT-authenticated access to scan management, results visualization, cloud credential management, and a real-time dashboard.

---

## Overview

This frontend is the operator-facing UI for the platform. It communicates with the FastAPI backend over REST (`/api/v1/*`) and receives real-time scan progress over an authenticated WebSocket (`/api/v1/ws/scan/{id}`). In production it is built into a static bundle and served by nginx alongside the API reverse proxy; in development it runs on the Vite dev server with HMR.

---

## Tech Stack

| Concern | Technology |
|---------|-----------|
| UI framework | React 19 |
| Build tool | Vite 8 |
| Language | TypeScript |
| Styling | Tailwind CSS 4 (via `@tailwindcss/vite`) |
| Server state | TanStack Query 5 |
| Tables | TanStack Table 8 |
| Client state | Zustand 5 |
| Forms | React Hook Form 7 + Zod 4 (via `@hookform/resolvers`) |
| Primitives | Radix UI (Dialog, Select, Switch, Tabs, Checkbox, Dropdown, Tooltip, Slot) |
| Charts | Recharts 3 |
| Icons | lucide-react |
| Routing | react-router-dom 7 |
| Utilities | clsx, tailwind-merge, class-variance-authority |

---

## Development Setup

### Prerequisites

- Node.js 22+ (matches the CI and Docker build)
- npm 10+
- A running backend (see the root [README](../README.md#development-setup)) — either local uvicorn or `docker compose up -d app`

### Install and run

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server starts on `http://localhost:5173` with HMR.

### Environment variables

Create a `.env` (or `.env.local`) in the `frontend/` directory:

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend API base URL. In production this is the nginx origin (same-origin). |
| `VITE_WS_BASE_URL` | derived from `VITE_API_BASE_URL` | WebSocket base URL. Defaults to the API host with `ws://` or `wss://`. |

> When running the frontend through the Docker `frontend` service, nginx proxies `/api/` and `/ws/` to the backend, so set `VITE_API_BASE_URL` to the same origin (or leave it empty to use relative paths).

---

## Build

```bash
# Type-check + production build
npm run build        # runs `tsc -b && vite build` → outputs to dist/

# Preview the production build locally
npm run preview
```

### Docker

The `frontend/Dockerfile` is a multi-stage build:

1. **Build stage** — `node:22-alpine`, runs `npm ci` and `npm run build`, producing `dist/`.
2. **Runtime stage** — `nginx:alpine`, copies `dist/` to the nginx document root and replaces the default config with `frontend/nginx.conf` (SPA fallback, API/WS reverse proxy, TLS termination).

```bash
# Build the image
docker build -t ipam-frontend ./frontend

# Or via compose (profile-gated)
docker compose --profile frontend up -d frontend
```

The frontend container exposes ports 80 (HTTP, redirected to HTTPS) and 443 (HTTPS). TLS certificates are mounted from `./nginx/certs/`.

---

## Project Structure

```
frontend/
├── src/
│   ├── main.tsx                # Application entry point
│   ├── App.tsx                 # Router + providers
│   ├── index.css               # Tailwind directives + global styles
│   ├── routes/                 # Page-level components
│   │   ├── Login.tsx           # JWT login page
│   │   ├── Dashboard.tsx       # KPI cards + charts
│   │   ├── Scans.tsx           # Scan list + creation
│   │   ├── ScanResults.tsx     # Per-scan results (ports + HTTP)
│   │   ├── Targets.tsx         # Scan target CRUD
│   │   ├── Credentials.tsx     # Cloud credential management
│   │   └── Settings.tsx        # User / application settings
│   ├── components/
│   │   ├── layout/             # Header, Sidebar, Layout
│   │   ├── dashboard/          # ScanOverview, PortDistribution, RecentScans, CloudStatus
│   │   ├── scans/              # ScanForm, ScanProgress, ScanResults
│   │   ├── ui/                 # 15 primitives (Button, Card, Badge, Input, Select,
│   │   │                       #   Dialog, Tabs, Switch, Checkbox, DataTable, KpiCard,
│   │   │                       #   ProgressBar, StatusBadge, Textarea, Toaster)
│   │   └── HealthCheck.tsx
│   ├── hooks/                  # useScans, useTargets, useProviders, useCredentials, useWebSocket
│   ├── stores/                 # authStore, uiStore, toastStore (Zustand)
│   ├── lib/                    # api.ts (fetch wrapper), websocket.ts, utils.ts
│   └── types/                  # api, scan, auth, analytics, websocket (TypeScript types)
├── public/                     # Static assets
├── nginx.conf                  # SPA + reverse-proxy config (baked into the image)
├── Dockerfile                  # Multi-stage node → nginx
├── package.json
├── tsconfig.json / tsconfig.app.json / tsconfig.node.json
├── vite.config.ts
└── eslint.config.js
```

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start the Vite dev server with HMR on port 5173 |
| `npm run build` | Type-check (`tsc -b`) then build the production bundle (`vite build`) |
| `npm run lint` | Run ESLint |
| `npm run preview` | Serve the production build locally for verification |

---

## Key Components

### Layout & navigation

- **`Layout`** — the authenticated shell with a sidebar and header; wraps all protected routes.
- **`Sidebar`** / **`Header`** — primary navigation between Dashboard, Scans, Targets, Credentials, Settings; displays the current user and logout.

### Dashboard

- **`ScanOverview`** — KPI cards (total scans, active scans, open ports, findings by severity) from `/scans/stats`.
- **`PortDistribution`** — bar chart of the most frequently open ports from `/analytics/port-distribution` (Recharts).
- **`RecentScans`** — table of recent scan jobs with status badges.
- **`CloudStatus`** — per-cloud-provider exposure summary.

### Scans

- **`ScanForm`** — create a scan job (select target, profile, toggles for banner grab / HTTP analysis) via `POST /scans/`.
- **`ScanProgress`** — real-time progress bar driven by the WebSocket stream (`useWebSocket` hook).
- **`ScanResults`** — tabbed view of port results (`DataTable`) and HTTP analyses per scan.

### UI primitives

The `components/ui/` directory contains 15 reusable primitives built on Radix UI and styled with Tailwind: `Button`, `Card`, `Badge`, `StatusBadge`, `Input`, `Textarea`, `Select`, `Dialog`, `Tabs`, `Switch`, `Checkbox`, `DataTable` (TanStack Table), `KpiCard`, `ProgressBar`, and `Toaster`.

### State management

- **`authStore`** (Zustand) — holds the JWT tokens, current user, and login/logout actions; drives the `Authorization` header in `lib/api.ts`.
- **`uiStore`** — UI preferences (sidebar collapse, theme).
- **`toastStore`** — transient notification queue rendered by `Toaster`.

### Data fetching

TanStack Query hooks in `src/hooks/` wrap the API calls and manage caching, refetching, and loading/error states. The WebSocket hook (`useWebSocket`) subscribes to the scan progress channel and updates query caches on `scan_complete` messages.

---

## Related Documentation

- [Root README](../README.md) — project overview and quick start
- [API reference](../docs/api.md) — full REST + WebSocket contract
- [Architecture](../docs/architecture.md) — system design
- [Security](../docs/security.md) — auth, encryption, headers
- [Deployment](../docs/deployment.md) — Docker, TLS, nginx
