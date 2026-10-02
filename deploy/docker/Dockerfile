# Next.Panel — multi-stage build (frontend + backend + minimal runtime).
#
# The frontend is built first so the Go binary embeds the UI (web/dist).
# SQLite needs no CGO (wasm driver), so the runtime image stays small.

# ---- frontend ----
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- backend ----
FROM golang:1.27-alpine AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -o /nextpanel ./cmd/nextpanel

# ---- runtime ----
FROM alpine:3.20
RUN adduser -D -u 10001 nextpanel \
  && apk add --no-cache ca-certificates tzdata
USER nextpanel
WORKDIR /data
COPY --from=backend /nextpanel /usr/local/bin/nextpanel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/nextpanel"]
