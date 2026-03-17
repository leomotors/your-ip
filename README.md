# Your IP

> [!NOTE]
> This project is almost 100% ai slop by Opus 4.6, including below readme

Minimal web application that shows the visitor's IP address, IP version, type classification, and detection method.

Built with Go `net/http` and a single embedded `index.html` — no dependencies, no frameworks, one binary.

## Features

- **Smart IP detection** — checks Cloudflare, Traefik, Nginx, Fastly, Akamai, and RFC 7239 `Forwarded` headers in priority order, falls back to `RemoteAddr`
- **IP classification** — Public, Private Class A/B/C, CGNAT, Loopback, Link-Local, IPv6 ULA
- **IPv4 / IPv6** version display
- **Frosted-glass UI** — light gradient, responsive, zero external assets
- **Single binary** — static files embedded via `go:embed`
- **Scratch Docker image** — minimal attack surface

## Quickstart

```bash
# Run in dev mode
make dev

# Build and preview
make preview

# Run tests
make test
```

## API

### `GET /api/ip`

Returns JSON with no-cache headers.

```json
{
  "ip": "203.0.113.50",
  "method": "Cloudflare (CF-Connecting-IP)",
  "ipType": "Public",
  "version": "IPv4"
}
```

## Docker

```bash
docker build -t your-ip .
docker run -p 8080:8080 your-ip
```

## Environment Variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PORT`   | `8080`  | Listen port |

## Makefile Targets

| Target    | Description                  |
| --------- | ---------------------------- |
| `dev`     | Run with `air` or `go run .` |
| `build`   | Compile binary               |
| `preview` | Build then run               |
| `format`  | `gofmt -w .`                 |
| `lint`    | `staticcheck` or `go vet`    |
| `test`    | Run tests with race detector |
| `clean`   | Remove build artifacts       |

## License

MIT
