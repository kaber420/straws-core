package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"strconv"
	_ "modernc.org/sqlite"
)

type ProxyRule struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"` // "engine" or "passthrough"
	Cert        string `json:"cert"`
}

// ProxyIdentity represents the structure of the JSON-encoded metadata in Proxy-Auth
type ProxyIdentity struct {
	TabID     int    `json:"tab"`
	WinID     int    `json:"win"`
	ChaosMode string `json:"chaos"`
	Container string `json:"cont"`
	Color     string `json:"color"`
}

type ProxyServer struct {
	Addr             string
	CertsDir         string
	LoggingEnabled   bool
	RecordingEnabled bool
	RecordingPath    string
	OnEvent          func(event map[string]interface{})
	certificates     map[string]tls.Certificate
	rules            map[string]ProxyRule
	rulesMu          sync.RWMutex
	db               *sql.DB

	// Live Chaos State
	chaosMu          sync.RWMutex
	chaosByTab       map[int]string
	chaosByContainer map[string]string
	// Chaos config: tabId -> ms value (for latency/jitter)
	chaosCfgByTab       map[int]int
	chaosCfgByContainer map[string]int
}

func (p *ProxyServer) Start() error {
	// Initialize chaos maps (MUST be done before any chaos operations)
	p.chaosByTab = make(map[int]string)
	p.chaosByContainer = make(map[string]string)
	p.chaosCfgByTab = make(map[int]int)
	p.chaosCfgByContainer = make(map[string]int)

	if p.CertsDir != "" {
		if err := p.LoadCertificates(); err != nil {
			log.Printf("Warning: error loading certificates: %v", err)
		}
	}

	if p.RecordingPath != "" {
		if err := p.initDB(); err != nil {
			log.Printf("Error initializing recording DB: %v", err)
		}
	}

	server := &http.Server{
		Addr:         p.Addr,
		Handler:      p,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	log.Printf("Starting Straws Engine on %s (Declarative Proxy Mode)", p.Addr)
	return server.ListenAndServe()
}

func (p *ProxyServer) initDB() error {
	var err error
	p.db, err = sql.Open("sqlite", p.RecordingPath)
	if err != nil {
		return err
	}

	query := `
	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		method TEXT,
		url TEXT,
		status INTEGER,
		latency TEXT,
		request_headers TEXT,
		request_body TEXT,
		response_headers TEXT,
		response_body TEXT
	);`
	_, err = p.db.Exec(query)
	return err
}

func normalizeHostname(host string) string {
	h := strings.TrimSpace(host)
	// Remove protocol
	if strings.Contains(h, "://") {
		parts := strings.SplitN(h, "://", 2)
		h = parts[1]
	}
	// Remove path
	if idx := strings.Index(h, "/"); idx != -1 {
		h = h[:idx]
	}
	// Remove port
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		// Check if it's truly a port (not part of an IPv6 address)
		if !strings.Contains(h, "]") || idx > strings.LastIndex(h, "]") {
			h = h[:idx]
		}
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func (p *ProxyServer) UpdateRules(newRules []ProxyRule) {
	p.rulesMu.Lock()
	defer p.rulesMu.Unlock()
	p.rules = make(map[string]ProxyRule)
	for _, r := range newRules {
		normalizedSource := normalizeHostname(r.Source)
		p.rules[normalizedSource] = r
		log.Printf("DEBUG: Rule Registered -> Source: %s (Normalized: %s), Destination: %s, Type: %s", r.Source, normalizedSource, r.Destination, r.Type)
	}
	log.Printf("Updated Rule Table: %d domains registered", len(newRules))
}

func (p *ProxyServer) getRule(host string) (ProxyRule, bool) {
	p.rulesMu.RLock()
	defer p.rulesMu.RUnlock()
	
	host = strings.ToLower(host)

	// 1. Exact match
	if rule, ok := p.rules[host]; ok {
		return rule, true
	}
	
	// 2. Wildcard and Subdomain check
	for source, rule := range p.rules {
		if strings.Contains(source, "*") {
			if matchWildcard(source, host) {
				return rule, true
			}
		} else {
			// Implicit subdomain check (e.g. api.mysite.local matches mysite.local)
			if strings.HasSuffix(host, "."+source) {
				return rule, true
			}
		}
	}
	
	return ProxyRule{}, false
}

func (p *ProxyServer) LoadCertificates() error {
	log.Printf("Scanning CertsDir: %s", p.CertsDir)
	p.certificates = make(map[string]tls.Certificate)
	if info, err := os.Stat(p.CertsDir); os.IsNotExist(err) {
		log.Printf("CRITICAL: Certs directory not found: %s", p.CertsDir)
		return fmt.Errorf("certificate directory not found: %s", p.CertsDir)
	} else if err == nil && !info.IsDir() {
		return fmt.Errorf("certs path is not a directory: %s", p.CertsDir)
	}
	
	files, err := os.ReadDir(p.CertsDir)
	if err != nil {
		log.Printf("ERROR: Failed to read certs dir: %v", err)
		return err
	}
	
	loadedCount := 0
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".crt") {
			base := strings.TrimSuffix(f.Name(), ".crt")
			keyPath := filepath.Join(p.CertsDir, base+".key")
			if _, err := os.Stat(keyPath); err == nil {
				cert, err := tls.LoadX509KeyPair(filepath.Join(p.CertsDir, f.Name()), keyPath)
				if err == nil {
					p.certificates[base] = cert
					leaf, err := x509.ParseCertificate(cert.Certificate[0])
					if err == nil {
						cert.Leaf = leaf
						for _, dnsName := range leaf.DNSNames {
							p.certificates[dnsName] = cert
						}
					}
					loadedCount++
				}
			}
		}
	}

	if loadedCount == 0 {
		return fmt.Errorf("no valid certificate/key pairs found in %s", p.CertsDir)
	}

	log.Printf("Successfully loaded %d certificate pairs from %s", loadedCount, p.CertsDir)
	return nil
}

func matchWildcard(pattern, host string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == host
	}
	parts := strings.Split(pattern, "*")
	if len(parts) != 2 {
		return false
	}
	return strings.HasPrefix(host, parts[0]) && strings.HasSuffix(host, parts[1])
}

func (p *ProxyServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	log.Printf("DEBUG: getCertificate request for ServerName: [%s]", hello.ServerName)
	if cert, ok := p.certificates[hello.ServerName]; ok {
		log.Printf("DEBUG: Exact match found for %s", hello.ServerName)
		return &cert, nil
	}
	for pattern, cert := range p.certificates {
		if cert.Leaf != nil {
			for _, name := range cert.Leaf.DNSNames {
				if matchWildcard(name, hello.ServerName) {
					log.Printf("DEBUG: Wildcard/SAN match found: %s matched %s", hello.ServerName, name)
					return &cert, nil
				}
			}
		} else {
			// Fallback for certs without Leaf info filled
			if matchWildcard(pattern, hello.ServerName) {
				log.Printf("DEBUG: Pattern match found: %s matched %s", hello.ServerName, pattern)
				return &cert, nil
			}
		}
	}
	log.Printf("DEBUG: No certificate found for %s. Available certs: %v", hello.ServerName, p.GetAvailableCerts())
	return nil, fmt.Errorf("no certificate for %s", hello.ServerName)
}

func (p *ProxyServer) GetAvailableCerts() []string {
	var names []string
	seen := make(map[string]bool)
	for name := range p.certificates {
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names
}

func (p *ProxyServer) DeleteCertificate(domain string) error {
	p.rulesMu.Lock()
	defer p.rulesMu.Unlock()

	// 1. Remove from memory
	delete(p.certificates, domain)
	
	// 2. Remove from disk if exists
	crtPath := filepath.Join(p.CertsDir, domain+".crt")
	keyPath := filepath.Join(p.CertsDir, domain+".key")
	
	errCrt := os.Remove(crtPath)
	errKey := os.Remove(keyPath)
	
	if errCrt != nil && !os.IsNotExist(errCrt) {
		return errCrt
	}
	if errKey != nil && !os.IsNotExist(errKey) {
		return errKey
	}
	
	log.Printf("Certificate for %s deleted successfully", domain)
	return nil
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Proxy-Authorization")
	log.Printf("[AUDIT] %s %s | Host: %s | Auth: %v", r.Method, r.URL.String(), r.Host, auth != "")

	host := r.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	rule, ok := p.getRule(host)
	if !ok {
		// FAIL FAST: Domain not declared
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Domain [%s] not registered in Straws Engine", host)
		return
	}

	// 407 HANDSHAKE: Force identity header if missing
	if auth == "" {
		log.Printf("[AUDIT] Missing Auth for %s, sending 407 challenge", host)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Straws Proxy"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, rule)
	} else {
		// Extract identity from Proxy-Authorization header
		tabId, _, container, _ := p.extractIdentity(r)
		// Chaos mode is always read from the live map (updated via Native Messaging)
		if p.applyChaos(w, r, tabId, container) {
			return
		}
		p.handleReverseProxy(w, r, rule)
	}
}

func (p *ProxyServer) handleReverseProxy(w http.ResponseWriter, r *http.Request, rule ProxyRule) {
	start := time.Now()
	
	targetHost := rule.Destination
	if !strings.Contains(targetHost, ":") {
		targetHost += ":80"
	}

	// Capture Request Data
	reqContentType := r.Header.Get("Content-Type")
	reqHeaders, _ := json.Marshal(r.Header)
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(reqBody)))
	}
	formattedReqBody := formatBody(reqBody, reqContentType)

	if p.LoggingEnabled && p.OnEvent != nil {
		p.OnEvent(map[string]interface{}{
			"type":   "http_start",
			"url":    r.URL.String(),
			"method": r.Method,
			"from":   "Straws Engine",
		})
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = targetHost
			req.Host = r.Host
			// CLEAN METADATA: Strip Proxy-Authorization before forwarding to target
			req.Header.Del("Proxy-Authorization")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("DEBUG: handleReverseProxy Error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			
			tabId, winId, _, _ := p.extractIdentity(r)
			event := map[string]interface{}{
				"type":    "http",
				"url":     r.URL.String(),
				"method":  r.Method,
				"status":  http.StatusBadGateway,
				"error":   err.Error(),
				"latency": time.Since(start).String(),
				"headers": map[string]interface{}{
					"request": r.Header,
				},
				"payload":   formattedReqBody,
				"from":      "Straws Engine",
				"tabId":     tabId,
				"windowId":  winId,
			}
			if p.LoggingEnabled && p.OnEvent != nil {
				p.OnEvent(event)
			}
		},
		ModifyResponse: func(res *http.Response) error {
			latency := time.Since(start).String()
			resHeaders, _ := json.Marshal(res.Header)
			resContentType := res.Header.Get("Content-Type")
			
			var resBody []byte
			if res.Body != nil {
				resBody, _ = io.ReadAll(res.Body)
				res.Body = io.NopCloser(strings.NewReader(string(resBody)))
			}
			formattedResBody := formatBody(resBody, resContentType)

			tabId, winId, _, chaosMode := p.extractIdentity(r)
			event := map[string]interface{}{
				"type":    "http",
				"url":     r.URL.String(),
				"method":  r.Method,
				"status":  res.StatusCode,
				"latency": latency,
				"chaos":   chaosMode != "",
				"headers": map[string]interface{}{
					"request":  r.Header,
					"response": res.Header,
				},
				"payload":  formattedReqBody,
				"response": formattedResBody,
				"from":     "Straws Engine",
				"tabId":    tabId,
				"windowId": winId,
			}

			if p.LoggingEnabled && p.OnEvent != nil {
				p.OnEvent(event)
			}

			if p.RecordingEnabled && p.db != nil {
				p.db.Exec(`INSERT INTO sessions (method, url, status, latency, request_headers, request_body, response_headers, response_body) 
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
					r.Method, r.URL.String(), res.StatusCode, latency, string(reqHeaders), string(reqBody), string(resHeaders), string(resBody))
			}

			return nil
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	proxy.ServeHTTP(w, r)
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request, rule ProxyRule) {
	start := time.Now()
	host := r.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	// 1. DECLARATIVE PASSTHROUGH (No TLS Termination)
	if rule.Type == "passthrough" {
		dest := rule.Destination
		if !strings.Contains(dest, ":") {
			dest += ":443"
		}
		
		destConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer destConn.Close()

		hijacker, ok := w.(http.Hijacker)
		if !ok { return }
		clientConn, _, err := hijacker.Hijack()
		if err != nil { return }
		defer clientConn.Close()

		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		go io.Copy(destConn, clientConn)
		io.Copy(clientConn, destConn)
		
		if p.LoggingEnabled && p.OnEvent != nil {
			p.OnEvent(map[string]interface{}{"type":"connect","host":host,"dest":dest,"mode":"passthrough","latency":time.Since(start).String()})
		}
		return
	}

	// 2. DECLARATIVE REVERSE PROXY (TLS Termination)
	// Extract identity ONCE from the CONNECT request for tabId/winId identification.
	// NOTE: chaosMode is intentionally NOT captured here — chaos state is read
	// from the live map on every inner request, enabling hot-activation/deactivation.
	tabId, winId, container, _ := p.extractIdentity(r)

	cert, err := p.getCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err == nil {
		log.Printf("DEBUG: handleConnect: Found cert for %s, hijacking connection...", host)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			log.Printf("ERROR: handleConnect: ResponseWriter does not support hijacking")
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			log.Printf("ERROR: handleConnect: Hijack failed: %v", err)
			return
		}

		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		tlsConn := tls.Server(clientConn, &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"}, // Allow H2 for performance
		})

		// Run in a goroutine to handle multiple requests (Keep-alive/Multiplexing)
		go func() {
			var reportHandshake sync.Once
			listener := &singleConnListener{conn: tlsConn}
			
			server := &http.Server{
				Handler: http.HandlerFunc(func(sw http.ResponseWriter, sr *http.Request) {
					// Optimized: Report TLS state once per connection, without blocking the handshake
					reportHandshake.Do(func() {
						if p.LoggingEnabled && p.OnEvent != nil {
							if sr.TLS != nil {
								peerCerts := len(sr.TLS.PeerCertificates)
								event := map[string]interface{}{
									"type": "tls_handshake",
									"host": host,
									"tls": map[string]interface{}{
										"sni":                 sr.TLS.ServerName,
										"tls_version":         getTLSVersionName(sr.TLS.Version),
										"cipher_suite":        getCipherSuiteName(sr.TLS.CipherSuite),
										"negotiated_protocol": sr.TLS.NegotiatedProtocol,
										"peer_certs":          peerCerts,
									},
									"from":     "Straws Engine",
									"tabId":    tabId,
									"windowId": winId,
								}
								p.OnEvent(event)
							}
						}
					})
					
					log.Printf("DEBUG: handleConnect: Decrypted request received for %s %s", sr.Method, sr.URL.String())
					
					// Apply Chaos: always read from the live map (NOT from captured CONNECT identity).
					// This enables hot-deactivation without closing the connection.
					if p.applyChaos(sw, sr, tabId, container) {
						return
					}

					if sr.URL.Host == "" {
						sr.URL.Host = host
						sr.URL.Scheme = "https"
					}
					// Propagate identity to inner requests robustly
					if auth := r.Header.Get("Proxy-Authorization"); auth != "" {
						sr.Header.Set("Proxy-Authorization", auth)
					}
					p.handleReverseProxy(sw, sr, rule)
				}),
				ErrorLog: log.New(io.Discard, "", 0),
			}

			// Serve the connection. Go's http.Server handles H2 automatically 
			// if it's negotiated in the TLS config.
			if err := server.Serve(listener); err != nil && err != io.EOF {
				log.Printf("DEBUG: handleConnect: TLS Proxy Server Error: %v", err)
			}
		}()
		return
	}

	// No cert and not passthrough -> Fail
	log.Printf("DEBUG: handleConnect: No certificate found for %s, failing...", host)
	http.Error(w, "No certificate found for registered host "+host, http.StatusServiceUnavailable)
}

// Helper to serve a single hijacked connection
type singleConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		l.done = make(chan struct{})
		c = l.conn
	})
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, io.EOF
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() {
		l.done = make(chan struct{})
	})
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func isTextual(contentType string) bool {
	ct := strings.ToLower(contentType)
	if ct == "" {
		return true
	}
	return strings.Contains(ct, "text") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "x-www-form-urlencoded") ||
		strings.Contains(ct, "graphql")
}

func formatBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > 100*1024 {
		return fmt.Sprintf("(Data too large: %d bytes)", len(body))
	}
	if !isTextual(contentType) {
		return fmt.Sprintf("(Binary Data: %s, %d bytes)", contentType, len(body))
	}
	return string(body)
}

func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", version)
	}
}

func getCipherSuiteName(id uint16) string {
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return suite.Name + " (Insecure)"
		}
	}
	return fmt.Sprintf("Unknown (0x%04X)", id)
}
func (p *ProxyServer) extractIdentity(r *http.Request) (tabId int, winId int, container string, chaosMode string) {
	tabId = -1
	winId = -1
	container = ""
	chaosMode = ""

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		// Try Proxy-Authorization in all-caps or other variants just in case
		for k, v := range r.Header {
			if strings.EqualFold(k, "Proxy-Authorization") && len(v) > 0 {
				auth = v[0]
				break
			}
		}
	}

	if !strings.HasPrefix(auth, "Basic ") {
		return tabId, winId, container, chaosMode
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[6:]))
	if err != nil {
		log.Printf("[TRACE] Error decoding Basic Auth Base64: %v", err)
		return tabId, winId, container, chaosMode
	}

	fullAuth := string(payload)
	lastColon := strings.LastIndex(fullAuth, ":")
	if lastColon == -1 {
		log.Printf("[TRACE] No colon found in decoded auth payload: %s", fullAuth)
		return tabId, winId, container, chaosMode
	}

	username := strings.TrimSpace(fullAuth[:lastColon])
	log.Printf("[TRACE] Raw Identity (Username): %s", username)

	// New JSON Format: username is a Base64-encoded JSON identity
	if jsonBytes, err := base64.StdEncoding.DecodeString(username); err == nil {
		ident := ProxyIdentity{TabID: -1, WinID: -1} // Default to -1 to differentiate from Tab 0
		if err := json.Unmarshal(jsonBytes, &ident); err == nil {
			log.Printf("[TRACE] Successfully Unmarshaled JSON: %+v", ident)
			return ident.TabID, ident.WinID, ident.Container, ident.ChaosMode
		} else {
			log.Printf("[TRACE] JSON Unmarshal error: %v | Raw JSON string: %s", err, string(jsonBytes))
		}
	} else {
		log.Printf("[TRACE] Username is NOT valid Base64 JSON (fallthrough to legacy): %v", err)
	}

	// Legacy Fallback
	tags := strings.Split(username, "|")
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if strings.HasPrefix(tag, "win:") || strings.HasPrefix(tag, "win=") {
			val, _ := strconv.Atoi(tag[4:])
			winId = val
		} else if strings.HasPrefix(tag, "tab:") || strings.HasPrefix(tag, "tab=") {
			val, _ := strconv.Atoi(tag[4:])
			tabId = val
		} else if (strings.HasPrefix(tag, "chaos:") || strings.HasPrefix(tag, "chaos=")) && len(tag) > 6 {
			sepIdx := strings.IndexAny(tag, ":=")
			if sepIdx != -1 {
				chaosMode = strings.TrimSpace(tag[sepIdx+1:])
			}
		}
	}

	return tabId, winId, container, chaosMode
}

func (p *ProxyServer) UpdateChaosMode(tabId int, container string, mode string, valueMs int) {
	p.chaosMu.Lock()
	defer p.chaosMu.Unlock()

	if mode == "" || mode == "none" {
		if tabId != -1 {
			delete(p.chaosByTab, tabId)
			delete(p.chaosCfgByTab, tabId)
		}
		if container != "" {
			delete(p.chaosByContainer, container)
			delete(p.chaosCfgByContainer, container)
		}
		log.Printf("[Chaos] Mode cleared for Tab %d / Container %s", tabId, container)
	} else {
		if tabId != -1 {
			p.chaosByTab[tabId] = mode
			if valueMs > 0 {
				p.chaosCfgByTab[tabId] = valueMs
			}
		}
		if container != "" {
			p.chaosByContainer[container] = mode
			if valueMs > 0 {
				p.chaosCfgByContainer[container] = valueMs
			}
		}
		log.Printf("[Chaos] Mode set to '%s' (%dms) for Tab %d / Container %s", mode, valueMs, tabId, container)
	}
}

// applyChaos reads chaos state from the live internal map (updated via Native Messaging
// sync_chaos command). This is the ONLY source of truth for chaos mode — NOT headers.
// This guarantees hot-activation and hot-deactivation work without closing connections.
func (p *ProxyServer) applyChaos(w http.ResponseWriter, r *http.Request, tabId int, container string) bool {
	p.chaosMu.RLock()
	mode := ""
	cfgMs := 0
	// Priority 1: Tab-specific chaos
	if tabId != -1 {
		mode = p.chaosByTab[tabId]
		cfgMs = p.chaosCfgByTab[tabId]
	}
	// Priority 2: Container-level chaos (fallback)
	if mode == "" && container != "" {
		mode = p.chaosByContainer[container]
		cfgMs = p.chaosCfgByContainer[container]
	}
	p.chaosMu.RUnlock()

	if mode == "" || mode == "none" {
		return false
	}

	log.Printf("[Chaos] Applying mode: '%s' (%dms) for host: %s (Tab %d/Cont %s)", mode, cfgMs, r.URL.Host, tabId, container)
	switch mode {
	case "latency":
		delay := 1000 // default 1s
		if cfgMs > 0 {
			delay = cfgMs
		}
		log.Printf("CHAOS: Injecting %dms latency for %s", delay, r.URL.Host)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	case "jitter":
		maxMs := 500 // default max 500ms
		if cfgMs > 0 {
			maxMs = cfgMs
		}
		j := rand.Intn(maxMs)
		log.Printf("CHAOS: Injecting %dms jitter for %s", j, r.URL.Host)
		time.Sleep(time.Duration(j) * time.Millisecond)
	case "drop":
		log.Printf("CHAOS: Dropping connection for %s", r.URL.Host)
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
				return true
			}
		}
		// Hijack not available (e.g. inside TLS tunnel with H2)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "Straws Chaos: Connection Dropped")
		return true
	case "error":
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Straws Chaos: Injected 500 Internal Server Error")
		return true
	}
	return false
}
