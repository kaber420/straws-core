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
	"encoding/json"
	_ "modernc.org/sqlite"
)

type ProxyRule struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"` // "engine" or "passthrough"
	Cert        string `json:"cert"`
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
}

func (p *ProxyServer) Start() error {
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

func (p *ProxyServer) UpdateRules(newRules []ProxyRule) {
	p.rulesMu.Lock()
	defer p.rulesMu.Unlock()
	p.rules = make(map[string]ProxyRule)
	for _, r := range newRules {
		p.rules[r.Source] = r
		log.Printf("DEBUG: Rule Registered -> Source: %s, Destination: %s, Type: %s", r.Source, r.Destination, r.Type)
	}
	log.Printf("Updated Rule Table: %d domains registered", len(newRules))
}

func (p *ProxyServer) getRule(host string) (ProxyRule, bool) {
	p.rulesMu.RLock()
	defer p.rulesMu.RUnlock()
	
	// 1. Exact match
	if rule, ok := p.rules[host]; ok {
		return rule, true
	}
	
	// 2. Subdomain check (e.g. api.mysite.local matches mysite.local)
	for source, rule := range p.rules {
		if strings.HasSuffix(host, "."+source) {
			return rule, true
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
	host := r.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	rule, ok := p.getRule(host)
	if !ok {
		// FAIL FAST: Domain not declared
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Domain [%s] not registered in Straws Engine", host)
		if p.LoggingEnabled && p.OnEvent != nil {
			p.OnEvent(map[string]interface{}{"type":"log","message":"Blocked unregistered host: "+host,"success":false})
		}
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, rule)
	} else {
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
			// Maintain the scheme (http or https) decided by the handler
			if req.URL.Scheme == "" {
				req.URL.Scheme = "http"
			}
			req.URL.Host = targetHost
			req.Host = r.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("DEBUG: handleReverseProxy Error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			
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
				"payload": formattedReqBody,
				"from": "Straws Engine",
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

			event := map[string]interface{}{
				"type":    "http",
				"url":     r.URL.String(),
				"method":  r.Method,
				"status":  res.StatusCode,
				"latency": latency,
				"headers": map[string]interface{}{
					"request": r.Header,
					"response": res.Header,
				},
				"payload": formattedReqBody,
				"response": formattedResBody,
				"from": "Straws Engine",
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
			NextProtos:   []string{"http/1.1"}, // Force HTTP/1.1 to avoid H2 negotiation issues on hijacked connections
		})
		
		// Run in a goroutine to handle multiple requests (Keep-alive)
		go func() {
			// Extract TLS metadata for the Handshake Inspector
			if err := tlsConn.Handshake(); err == nil {
				state := tlsConn.ConnectionState()
				peerCerts := len(state.PeerCertificates)
				
				event := map[string]interface{}{
					"type": "tls",
					"host": host,
					"tls": map[string]interface{}{
						"sni":                 state.ServerName,
						"tls_version":         getTLSVersionName(state.Version),
						"cipher_suite":        getCipherSuiteName(state.CipherSuite),
						"negotiated_protocol": state.NegotiatedProtocol,
						"peer_certs":          peerCerts,
					},
					"from": "Straws Engine",
				}
				if p.LoggingEnabled && p.OnEvent != nil {
					p.OnEvent(event)
				}
			} else {
				log.Printf("DEBUG: handleConnect: TLS Handshake failed for %s: %v", host, err)
				if p.LoggingEnabled && p.OnEvent != nil {
					p.OnEvent(map[string]interface{}{
						"type": "error",
						"from": "Straws Engine",
						"message": fmt.Sprintf("TLS Handshake failure for %s: %v", host, err),
					})
				}
				tlsConn.Close()
				return
			}

			listener := &singleConnListener{conn: tlsConn}
			server := &http.Server{
				Handler: http.HandlerFunc(func(sw http.ResponseWriter, sr *http.Request) {
					log.Printf("DEBUG: handleConnect: Decrypted request received for %s %s", sr.Method, sr.URL.String())
					if sr.URL.Host == "" {
						sr.URL.Host = host
						sr.URL.Scheme = "https"
					}
					p.handleReverseProxy(sw, sr, rule)
				}),
				ErrorLog: log.New(io.Discard, "", 0),
			}
			
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
