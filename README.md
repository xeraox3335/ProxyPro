# ProxyPro

A lightweight HTTP/HTTPS proxy server you can deploy on [render.com](https://render.com) for **free** and use directly from your browser's built-in proxy settings.

## Features

- **HTTP proxy** — forwards `GET`, `POST`, and all other HTTP methods
- **HTTPS tunnelling** — handles browser `CONNECT` requests so HTTPS sites work through the proxy
- **Optional Basic authentication** — protect your proxy with a username and password
- **SSRF protection** — blocks requests to loopback, private, and link-local IP ranges (e.g. `127.x.x.x`, `10.x.x.x`, `192.168.x.x`, `169.254.169.254`)
- **Hop-by-hop header removal** — compliant RFC 7230 forwarding
- **Zero runtime dependencies** — uses only Node.js built-in modules

---

## Deploy to render.com (free)

1. **Fork or push this repo** to your GitHub / GitLab account.

2. Go to [render.com](https://render.com) → **New → Web Service**.

3. Connect your repository. render.com will detect the `render.yaml` and pre-fill the settings.

4. (Optional) Add environment variables for authentication:

   | Key          | Value         |
   |--------------|---------------|
   | `PROXY_USER` | your username |
   | `PROXY_PASS` | your password |

   Leave both blank to run as an open (unauthenticated) proxy.

5. Click **Create Web Service**. render.com will build and start the server.

Your proxy URL will be `https://<your-app>.onrender.com`.

---

## Configure your browser

### Firefox

1. Open **Settings** → scroll to **Network Settings** → click **Settings…**
2. Select **Manual proxy configuration**
3. Set **HTTP Proxy** to `<your-app>.onrender.com` and **Port** to `443`
4. Check **Also use this proxy for HTTPS**
5. Click **OK**

If you enabled authentication, Firefox will prompt for your credentials the first time you make a request.

### Chrome / Chromium (via system proxy)

Chrome on Linux/macOS follows the OS proxy settings:

1. Go to **System Preferences / Settings → Network → Proxy**
2. Enable **Web Proxy (HTTP)** and **Secure Web Proxy (HTTPS)**
3. Enter `<your-app>.onrender.com` and port `443` for both

---

## Run locally

```bash
# No install required — uses only built-in Node.js modules (Node ≥ 18)
node server.js
# Server listens on port 8080 by default

# With authentication
PROXY_USER=alice PROXY_PASS=secret node server.js

# Custom port
PORT=3128 node server.js
```

Test it with curl:

```bash
curl -x http://localhost:8080 http://example.com/
# With auth:
curl -x http://alice:secret@localhost:8080 http://example.com/
```

---

## Environment variables

| Variable     | Default | Description                                      |
|--------------|---------|--------------------------------------------------|
| `PORT`       | `8080`  | Port to listen on (render.com sets this for you) |
| `PROXY_USER` | *(none)*| Basic auth username (leave empty to disable auth)|
| `PROXY_PASS` | *(none)*| Basic auth password (leave empty to disable auth)|

---

## Run tests

```bash
node --test test/
```

---

## Architecture notes

render.com's free tier terminates TLS at the edge and forwards plain HTTP to your service. This means:

- **HTTP traffic** is fully proxied through the service.
- **HTTPS traffic** — the browser sends a `CONNECT` request over the already-TLS-terminated connection. render.com forwards the `CONNECT` request to ProxyPro, which then opens a raw TCP tunnel to the target. The browser's TLS handshake with the destination server travels through this tunnel end-to-end.

> **Note:** render.com free-tier web services spin down after 15 minutes of inactivity and restart on the next request (cold start ~30 s). For continuous proxy use, consider upgrading to a paid plan or keep-alive pings.
