package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type CertGenerator interface {
	GetCACert() *x509.Certificate
	GetCAKey() interface{}
	IsCAInstalled() bool
}

type ProxyServer struct {
	Server        *http.Server
	listenAddr    string
	rules         *RuleManager
	running       bool
	mode          string // global runtime mode: "mitm" | "transparent"
	mu            sync.RWMutex
	certCacheMu   sync.RWMutex
	certCache     map[string]*tls.Certificate
	Fingerprint   string
	certGenerator CertGenerator
	recentIngress []string
	dohResolver   *DoHResolver
	cfPool        *CloudflarePool
	transport     *http.Transport
}

type RuleManager struct {
	rules            []Rule
	siteGroups       []SiteGroup
	upstreams        []Upstream
	configPath       string
	cloudflareConfig CloudflareConfig
	serverHost       string
	serverAuth       string
	mu               sync.RWMutex
}

type SiteGroup struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Website       string   `json:"website,omitempty"`
	Domains       []string `json:"domains"`
	Mode          string   `json:"mode"`
	Upstream      string   `json:"upstream"`
	Upstreams     []string `json:"upstreams,omitempty"`
	SniFake       string   `json:"sni_fake"`
	ConnectPolicy string   `json:"connect_policy,omitempty"` // "", "tunnel_origin", "tunnel_upstream", "mitm", "direct"
	SniPolicy     string   `json:"sni_policy,omitempty"`     // "", "auto", "original", "fake", "upstream", "none"
	AlpnPolicy    string   `json:"alpn_policy,omitempty"`    // "", "auto", "h1_only", "h2_h1"
	UTLSPolicy    string   `json:"utls_policy,omitempty"`    // "", "auto", "on", "off"
	Enabled       bool     `json:"enabled"`
	ECHEnabled    bool     `json:"ech_enabled"`
	ECHDomain     string   `json:"ech_domain"` // Domain used for ECH DoH lookup
	UseCFPool     bool     `json:"use_cf_pool"`
}

type Upstream struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}

type Config struct {
	ListenPort       string           `json:"listen_port"`
	ServerHost       string           `json:"server_host,omitempty"`
	ServerAuth       string           `json:"server_auth,omitempty"`
	SiteGroups       []SiteGroup      `json:"site_groups"`
	Upstreams        []Upstream       `json:"upstreams"`
	CloudflareConfig CloudflareConfig `json:"cloudflare_config"`
}

type CloudflareConfig struct {
	PreferredIPs []string `json:"preferred_ips"`
	DoHURL       string   `json:"doh_url"`
	AutoUpdate   bool     `json:"auto_update"`
	APIKey       string   `json:"api_key"`
}


type trackingListener struct {
	net.Listener
	proxy *ProxyServer
}

type singleConnListener struct {
	conn      net.Conn
	once      sync.Once
	done      chan struct{}
	doneOnce  sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var accepted bool
	l.once.Do(func() { accepted = true })
	if accepted {
		return &notifyCloseConn{
			Conn: l.conn,
			onClose: func() {
				l.doneOnce.Do(func() { close(l.done) })
			},
		}, nil
	}
	<-l.done
	return nil, io.EOF
}
func (l *singleConnListener) Close() error {
	l.doneOnce.Do(func() { close(l.done) })
	return nil
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyCloseConn struct {
	net.Conn
	onClose func()
}

func (c *notifyCloseConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

type roundTripperFunc func(*http.Request) (*http.Response, error)
func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func (l *trackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type Rule struct {
	Domain        string
	Upstream      string
	Upstreams     []string
	Mode          string // "mitm", "transparent", "direct"
	SniFake       string
	ConnectPolicy string // "", "tunnel_origin", "tunnel_upstream", "mitm", "direct"
	SniPolicy     string // "", "auto", "original", "fake", "upstream", "none"
	AlpnPolicy    string // "", "auto", "h1_only", "h2_h1"
	UTLSPolicy    string // "", "auto", "on", "off"
	Enabled       bool
	SiteID        string
	ECHEnabled    bool
	ECHDomain     string
	UseCFPool     bool
}

func mergeRule(base, overlay Rule) Rule {
	out := base
	if strings.TrimSpace(overlay.Upstream) != "" {
		out.Upstream = overlay.Upstream
	}
	if len(overlay.Upstreams) > 0 {
		out.Upstreams = append([]string(nil), overlay.Upstreams...)
	}
	if strings.TrimSpace(overlay.SniFake) != "" {
		out.SniFake = overlay.SniFake
	}
	if strings.TrimSpace(overlay.ConnectPolicy) != "" {
		out.ConnectPolicy = overlay.ConnectPolicy
	}
	if strings.TrimSpace(overlay.SniPolicy) != "" {
		out.SniPolicy = overlay.SniPolicy
	}
	if strings.TrimSpace(overlay.AlpnPolicy) != "" {
		out.AlpnPolicy = overlay.AlpnPolicy
	}
	if strings.TrimSpace(overlay.UTLSPolicy) != "" {
		out.UTLSPolicy = overlay.UTLSPolicy
	}
	return out
}

type bufferedReadConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedReadConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// WriteTo must be implemented to prevent io.Copy from using the embedded Conn's WriteTo method,
// which would bypass c.reader (and the buffered data) and read directly from the file descriptor.
func (c *bufferedReadConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, c.reader)
}

func wrapHijackedConn(conn net.Conn, rw *bufio.ReadWriter) net.Conn {
	if rw == nil || rw.Reader == nil || rw.Reader.Buffered() == 0 {
		return conn
	}
	// Extract buffered bytes to avoid sticking with bufio.Reader
	n := rw.Reader.Buffered()
	buffered := make([]byte, n)
	_, _ = rw.Reader.Read(buffered)

	return &bufferedReadConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(buffered), conn),
	}
}

func normalizeHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(host))
	}

	// Missing port or bracket-only IPv6 literals should still match rules.
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"))
	}

	return strings.ToLower(hostport)
}

func cleanWebsiteToken(token string) string {
	token = normalizeHost(token)
	token = strings.TrimPrefix(token, "*.")
	token = strings.TrimSuffix(token, "$")
	token = strings.Trim(token, "[]")
	if i := strings.Index(token, ":"); i >= 0 {
		token = token[:i]
	}
	return token
}

func tokenMatchesDomain(token, domain string) bool {
	token = cleanWebsiteToken(token)
	domain = cleanWebsiteToken(domain)
	if token == "" || domain == "" {
		return false
	}
	return token == domain || strings.HasSuffix(token, "."+domain)
}

func inferWebsiteFromSiteGroup(sg SiteGroup) string {
	tokens := []string{sg.Name, sg.Upstream, sg.SniFake}
	tokens = append(tokens, sg.Domains...)

	hasDomain := func(domains ...string) bool {
		for _, t := range tokens {
			for _, d := range domains {
				if tokenMatchesDomain(t, d) {
					return true
				}
			}
		}
		return false
	}

	switch {
	case hasDomain("google.com", "youtube.com", "gstatic.com", "googlevideo.com", "gvt1.com", "ytimg.com", "youtu.be", "ggpht.com"):
		return "google"
	case hasDomain("github.com", "githubusercontent.com", "githubassets.com", "github.io"):
		return "github"
	case hasDomain("telegram.org", "web.telegram.org", "cdn-telegram.org", "t.me", "telesco.pe", "tg.dev", "telegram.me"):
		return "telegram"
	case hasDomain("proton.me"):
		return "proton"
	case hasDomain("pixiv.net", "fanbox.cc", "pximg.net", "pixiv.org"):
		return "pixiv"
	case hasDomain("nyaa.si"):
		return "nyaa"
	case hasDomain("wikipedia.org", "wikimedia.org", "mediawiki.org", "wikibooks.org", "wikidata.org", "wikifunctions.org", "wikinews.org", "wikiquote.org", "wikisource.org", "wikiversity.org", "wikivoyage.org", "wiktionary.org"):
		return "wikipedia"
	case hasDomain("e-hentai.org", "exhentai.org", "ehgt.org", "hentaiverse.org", "ehwiki.org", "ehtracker.org"):
		return "ehentai"
	case hasDomain("facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "instagr.am", "ig.me", "whatsapp.com", "whatsapp.net"):
		return "meta"
	case hasDomain("twitter.com", "x.com", "t.co", "twimg.com"):
		return "x"
	case hasDomain("steamcommunity.com", "steampowered.com"):
		return "steam"
	case hasDomain("mega.nz", "mega.io", "mega.co.nz"):
		return "mega"
	case hasDomain("dailymotion.com"):
		return "dailymotion"
	case hasDomain("duckduckgo.com"):
		return "duckduckgo"
	case hasDomain("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"):
		return "reddit"
	case hasDomain("twitch.tv"):
		return "twitch"
	case hasDomain("bbc.com", "bbc.co.uk", "bbci.co.uk"):
		return "bbc"
	}

	for _, d := range sg.Domains {
		d = cleanWebsiteToken(d)
		if d == "" || d == "off" {
			continue
		}
		parts := strings.Split(d, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2]
		}
		return d
	}

	for _, t := range tokens {
		t = cleanWebsiteToken(t)
		if t == "" || t == "off" {
			continue
		}
		parts := strings.Split(t, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2]
		}
		return t
	}
	return "misc"
}

func ensureAddrWithPort(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if port == "" {
			port = defaultPort
		}
		return net.JoinHostPort(host, port)
	}

	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), defaultPort)
	}

	return net.JoinHostPort(addr, defaultPort)
}

func resolveUpstreamHost(targetHost, upstream string) string {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" {
		return ""
	}
	if strings.Contains(upstream, "$1") {
		firstLabel := targetHost
		if i := strings.Index(firstLabel, "."); i > 0 {
			firstLabel = firstLabel[:i]
		}
		upstream = strings.ReplaceAll(upstream, "$1", firstLabel)
	}
	return upstream
}

func resolveRuleUpstream(targetHost string, rule Rule) string {
	resolved := resolveUpstreamHost(targetHost, rule.Upstream)
	trimmed := strings.TrimSpace(resolved)
	if trimmed == "" && len(rule.Upstreams) > 0 {
		return strings.Join(rule.Upstreams, ",")
	}

	low := strings.ToLower(trimmed)
	if strings.HasPrefix(low, "$backend_ip") || strings.HasPrefix(low, "$upstream_host") || strings.HasPrefix(trimmed, "$") {
		if len(rule.Upstreams) > 0 {
			return strings.Join(rule.Upstreams, ",")
		}
		return net.JoinHostPort(targetHost, "443")
	}

	return resolved
}

func splitUpstreamCandidates(targetHost, upstream, defaultPort string) []string {
	resolved := resolveUpstreamHost(targetHost, upstream)
	if resolved == "" {
		return nil
	}
	parts := strings.Split(resolved, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		addr := ensureAddrWithPort(strings.TrimSpace(p), defaultPort)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func firstUpstreamHost(targetHost, upstream string) string {
	candidates := splitUpstreamCandidates(targetHost, upstream, "443")
	if len(candidates) == 0 {
		return ""
	}
	host, _, err := net.SplitHostPort(candidates[0])
	if err != nil {
		return normalizeHost(candidates[0])
	}
	return normalizeHost(host)
}

func hostMatchesDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return false
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, "$")

	// Extended pattern syntax: google.com.* (or any base.*)
	// Matches google.com.sg, www.google.com.sg, google.com.hk, etc.
	if strings.HasSuffix(domain, ".*") {
		base := strings.TrimSuffix(domain, ".*")
		if base == "" {
			return false
		}
		hostParts := strings.Split(host, ".")
		baseParts := strings.Split(base, ".")
		if len(hostParts) < len(baseParts)+1 {
			return false
		}
		for i := 0; i+len(baseParts) < len(hostParts); i++ {
			ok := true
			for j := 0; j < len(baseParts); j++ {
				if hostParts[i+j] != baseParts[j] {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}

	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func domainMatchScore(host, domain string) int {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return -1
	}

	if strings.HasPrefix(domain, "~") {
		pattern := strings.TrimSpace(strings.TrimPrefix(domain, "~"))
		if pattern == "" {
			return -1
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return -1
		}
		if re.MatchString(host) {
			return 900 + len(pattern) // exact(1000+) > regex(900+) > suffix/exact-domain
		}
		return -1
	}

	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, "$")

	// Pattern base.* => give base length score when matched.
	if strings.HasSuffix(domain, ".*") {
		base := strings.TrimSuffix(domain, ".*")
		if base == "" {
			return -1
		}
		hostParts := strings.Split(host, ".")
		baseParts := strings.Split(base, ".")
		if len(hostParts) < len(baseParts)+1 {
			return -1
		}
		for i := 0; i+len(baseParts) < len(hostParts); i++ {
			ok := true
			for j := 0; j < len(baseParts); j++ {
				if hostParts[i+j] != baseParts[j] {
					ok = false
					break
				}
			}
			if ok {
				return len(base)
			}
		}
		return -1
	}

	if host == domain {
		return len(domain) + 1000 // Prefer exact match over suffix match.
	}
	if strings.HasSuffix(host, "."+domain) {
		return len(domain)
	}
	return -1
}

func isLiteralIP(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

func chooseUpstreamSNI(targetHost string, rule Rule) string {
	targetHost = normalizeHost(targetHost)
	hostAsToken := strings.Trim(targetHost, "[]")
	hostAsToken = strings.ReplaceAll(hostAsToken, ".", "-")
	hostAsToken = strings.ReplaceAll(hostAsToken, ":", "-")
	hostAsToken = strings.TrimSpace(hostAsToken)
	if hostAsToken == "" {
		hostAsToken = "g-cn"
	}
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)

	switch strings.ToLower(strings.TrimSpace(rule.SniPolicy)) {
	case "none":
		// Explicitly disable SNI extension for upstream TLS ClientHello.
		return ""
	case "original":
		return targetHost
	case "fake":
		if strings.TrimSpace(rule.SniFake) != "" {
			return rule.SniFake
		}
		return hostAsToken
	case "upstream":
		if upstreamHost := firstUpstreamHost(targetHost, resolvedUpstream); upstreamHost != "" && !isLiteralIP(upstreamHost) {
			return upstreamHost
		}
		return targetHost
	}

	// MITM mode's core behavior: if fake SNI is configured, always use it.
	if strings.TrimSpace(rule.SniFake) != "" {
		return rule.SniFake
	}
	if resolvedUpstream != "" {
		if upstreamHost := firstUpstreamHost(targetHost, resolvedUpstream); upstreamHost != "" {
			if !isLiteralIP(upstreamHost) && upstreamHost != targetHost {
				return upstreamHost
			}
		}
	}
	// Auto mode should be predictable: when no fake/upstream SNI is available,
	// fall back to original host instead of implicit camouflage.
	return targetHost
}

func NewProxyServer(addr string) *ProxyServer {
	p := &ProxyServer{
		listenAddr:  addr,
		certCache:   make(map[string]*tls.Certificate),
		Fingerprint: "chrome", // default
		mode:        "mitm",   // default
		transport: &http.Transport{
			Proxy: nil, // We are the proxy
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   10,
		},
		dohResolver: NewDoHResolver(""),
		cfPool:      NewCloudflarePool([]string{}),
	}
	p.rules = NewRuleManager("")
	return p
}

func (p *ProxyServer) SetRuleManager(rm *RuleManager) {
	p.mu.Lock()
	p.rules = rm
	if rm != nil {
		cfg := rm.GetCloudflareConfig()
		if p.dohResolver != nil {
			p.dohResolver.ServerURL = cfg.DoHURL
			if p.dohResolver.ServerURL == "" {
				p.dohResolver.ServerURL = "https://223.5.5.5/dns-query"
			}
		}
		if p.cfPool != nil {
			p.cfPool.UpdateIPs(cfg.PreferredIPs)
		}
	}
	p.mu.Unlock()
}

func (p *ProxyServer) SetCertGenerator(cg CertGenerator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certGenerator = cg
}

func (p *ProxyServer) UpdateCloudflareConfig(cfg CloudflareConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dohResolver != nil {
		p.dohResolver.ServerURL = cfg.DoHURL
		if p.dohResolver.ServerURL == "" {
			p.dohResolver.ServerURL = "https://223.5.5.5/dns-query"
		}
	}
	if p.cfPool != nil {
		p.cfPool.UpdateIPs(cfg.PreferredIPs)
	}
}

func (p *ProxyServer) UpdateCloudflareIPPool(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfPool != nil {
		p.cfPool.UpdateIPs(ips)
	}
}

func (p *ProxyServer) SetListenAddr(addr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return fmt.Errorf("cannot change address while proxy is running")
	}
	p.listenAddr = addr
	return nil
}

func (p *ProxyServer) TriggerCFHealthCheck() {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cfPool != nil {
		p.cfPool.TriggerHealthCheck()
	}
}

func (p *ProxyServer) RemoveInvalidCFIPs() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cfPool != nil {
		return p.cfPool.RemoveInvalidIPs()
	}
	return 0
}

func (p *ProxyServer) GetAllCFIPsWithStats() []*IPStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cfPool != nil {
		return p.cfPool.GetAllIPsWithStats()
	}
	return nil
}

func (p *ProxyServer) GetListenAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.listenAddr
}

func (p *ProxyServer) SetMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "mitm" && mode != "transparent" {
		return fmt.Errorf("invalid proxy mode: %s", mode)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode = mode
	return nil
}

func (p *ProxyServer) GetMode() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mode
}

func (p *ProxyServer) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}

	srv := &http.Server{
		Addr: p.listenAddr,
		// Use raw handler instead of ServeMux: CONNECT uses authority-form
		// and may not be routed by path-based muxes.
		Handler:      http.HandlerFunc(p.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	listenAddr := p.listenAddr
	
	if p.cfPool != nil {
		p.cfPool.Start()
	}
	p.mu.Unlock()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		// Clean up pool if listen fails
		if p.cfPool != nil {
			p.cfPool.Stop()
		}
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	p.mu.Lock()
	// Re-check state in case Stop/Start race happened while binding.
	if p.running {
		p.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	p.Server = srv
	p.running = true
	p.mu.Unlock()

	go func() {
		log.Printf("[Proxy] Server started on %s", listenAddr)
		tl := &trackingListener{
			Listener: ln,
			proxy:    p,
		}
		if err := srv.Serve(tl); err != nil && err != http.ErrServerClosed {
			log.Printf("[Proxy] Server error: %v", err)
		}
		p.mu.Lock()
		if p.Server == srv {
			p.running = false
		}
		p.mu.Unlock()
	}()

	return nil
}

func (p *ProxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return nil
	}
	p.running = false
	
	if p.cfPool != nil {
		p.cfPool.Stop()
	}

	if p.Server != nil {
		return p.Server.Close()
	}
	return nil
}

func (p *ProxyServer) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

func (p *ProxyServer) handleRequest(w http.ResponseWriter, req *http.Request) {

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	matchHost := normalizeHost(host)
	mode := p.GetMode()
	rule := p.rules.matchRule(matchHost, mode)
	if rule.SiteID != "" {
		p.rules.incrementRuleHit(rule.SiteID)
	}

	log.Printf("[Proxy] Request: %s -> %s (match: %s, runtime-mode: %s, rule-mode: %s)", req.Method, host, matchHost, mode, rule.Mode)

	switch req.Method {
	case http.MethodConnect:
		p.handleConnect(w, req, rule)
	default:
		p.handleHTTP(w, req, rule)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, req *http.Request, rule Rule) {

	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetHost := normalizeHost(targetAuthority)
	targetAddr := ensureAddrWithPort(targetAuthority, "443")
	effectiveMode := rule.Mode
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)

	switch strings.ToLower(strings.TrimSpace(rule.ConnectPolicy)) {
	case "tunnel_origin":
		effectiveMode = "transparent"
		resolvedUpstream = ""
	case "tunnel_upstream":
		effectiveMode = "transparent"
	case "mitm":
		effectiveMode = "mitm"
	case "direct":
		effectiveMode = "direct"
		resolvedUpstream = ""
	}

	// Stage-2 match: if stage-1 produced a dynamic upstream host (eg. *.gvt1.com),
	// allow that upstream host to hit another rule and override policies.
	if (effectiveMode == "mitm" || effectiveMode == "transparent") && strings.TrimSpace(resolvedUpstream) != "" {
		upHost := firstUpstreamHost(targetHost, resolvedUpstream)
		if upHost != "" {
			upRule := p.rules.matchRule(upHost, effectiveMode)
			if upRule.SiteID != "" {
				baseSite := rule.SiteID
				rule = mergeRule(rule, upRule)
				if strings.TrimSpace(rule.Upstream) != "" {
					resolvedUpstream = resolveRuleUpstream(upHost, rule)
				}
				log.Printf("[Connect] Stage-2 upstream rule applied: host=%s site=%s over base=%s", upHost, upRule.SiteID, baseSite)
			}
		}
	}

	log.Printf("[Connect] target=%s host=%s mode=%s->%s upstream=%s sni_fake=%s", targetAddr, targetHost, rule.Mode, effectiveMode, resolvedUpstream, rule.SniFake)

	// 对于 direct 模式，直接连接目标
	if effectiveMode == "direct" {
		p.directConnect(w, req)
		return
	}

	// 对于 server 模式，直接劫持并使用内置 HTTP 服务解析，不进行原目标拨号
	if effectiveMode == "server" {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, rw, err := hijacker.Hijack()
		if err != nil {
			log.Printf("[Connect] Server hijack failed: %v", err)
			return
		}
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			clientConn.Close()
			return
		}
		if err := rw.Flush(); err != nil {
			clientConn.Close()
			return
		}
		clientConn = wrapHijackedConn(clientConn, rw)
		_ = clientConn.SetDeadline(time.Time{})
		p.handleServerMITM(clientConn, targetHost, rule)
		return
	}

	var conn net.Conn
	var err error
	dialAddr := targetAddr
	dialCandidates := []string{dialAddr}

	// For MITM/transparent rules, upstream should be respected if configured.
	if (effectiveMode == "mitm" || effectiveMode == "transparent") && strings.TrimSpace(resolvedUpstream) != "" {
		dialCandidates = splitUpstreamCandidates(targetHost, resolvedUpstream, "443")
		if len(dialCandidates) == 0 {
			dialCandidates = []string{targetAddr}
		}
		dialAddr = dialCandidates[0]
		log.Printf("[Connect] Using upstream candidates %v for host %s (mode: %s)", dialCandidates, targetHost, effectiveMode)
	}

	// Cloudflare Preferred IP Pool integration
	if rule.UseCFPool && p.cfPool != nil {
		topIPs := p.cfPool.GetTopIPs(5)
		if len(topIPs) > 0 {
			var prefs []string
			for _, ip := range topIPs {
				prefs = append(prefs, net.JoinHostPort(ip, "443"))
			}

			if strings.TrimSpace(resolvedUpstream) == "" {
				// upstream 为空，只用 CF pool IP
				dialCandidates = prefs
			} else {
				// 有配置 upstream，CF pool 作为首选加速项
				dialCandidates = append(prefs, dialCandidates...)
			}
			dialAddr = prefs[0]
			log.Printf("[Connect] Using %d preferred Cloudflare IPs (best: %s) for %s", len(topIPs), topIPs[0], targetHost)
		}
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	// 单路稳定性优先（结合顺序回退）
	if len(dialCandidates) > 1 {
		var lastErr error
		for _, addr := range dialCandidates {
			conn, err = dialer.Dial("tcp", addr)
			if err == nil {
				dialAddr = addr
				log.Printf("[Connect] Sequential dial success: %s", dialAddr)
				
				// 如果使用了 CF 优选池，回馈成功状态
				if rule.UseCFPool && p.cfPool != nil {
					host, _, _ := net.SplitHostPort(addr)
					if host != "" {
						p.cfPool.ReportSuccess(host)
					}
				}
				break
			}
			
			log.Printf("[Connect] Connect failed to %s: %v", addr, err)
			lastErr = err
			
			// 如果该候选节点连通失败，且来自于 CF 优选池，上报失败实施惩罚
			if rule.UseCFPool && p.cfPool != nil {
				host, _, _ := net.SplitHostPort(addr)
				if host != "" {
					p.cfPool.ReportFailure(host)
				}
			}
		}
		if conn == nil {
			err = lastErr
		}
	} else {
		for _, candidate := range dialCandidates {
			conn, err = dialer.Dial("tcp", candidate)
			if err == nil {
				dialAddr = candidate
				break
			}
			log.Printf("[Connect] Connect failed to %s: %v", candidate, err)
		}
	}
	if err != nil || conn == nil {
		http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
		log.Printf("[Connect] All upstream connect attempts failed: %v", dialCandidates)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		conn.Close()
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[Connect] Hijack failed: %v", err)
		conn.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[Connect] Write 200 failed: %v", err)
		clientConn.Close()
		conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		log.Printf("[Connect] Flush 200 failed: %v", err)
		clientConn.Close()
		conn.Close()
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	_ = clientConn.SetDeadline(time.Time{})
	_ = conn.SetDeadline(time.Time{})

	// 注意：不要在 hijack 后使用 defer，因为我们需要保持连接打开
	if effectiveMode == "mitm" {
		p.handleMITM(clientConn, targetHost, rule, dialCandidates, dialAddr)
	} else {
		p.handleTransparent(clientConn, conn, targetHost, rule)
	}
}

func (p *ProxyServer) directConnect(w http.ResponseWriter, req *http.Request) {
	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetAddr := ensureAddrWithPort(targetAuthority, "443")

	log.Printf("[Direct] Connecting to %s", targetAddr)

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		conn.Close()
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		conn.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			clientConn.Close()
		conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
			clientConn.Close()
		conn.Close()
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	_ = clientConn.SetDeadline(time.Time{})
	_ = conn.SetDeadline(time.Time{})

	// 双向复制数据
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		_, _ = io.CopyBuffer(conn, clientConn, buf)
		conn.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		_, _ = io.CopyBuffer(clientConn, conn, buf)
		clientConn.Close()
	}()
	wg.Wait()
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, req *http.Request, rule Rule) {
	// 创建新的请求，避免修改原始请求
	newReq := req.Clone(req.Context())
	newReq.RequestURI = ""
	newReq.Header.Del("Proxy-Connection")

	if newReq.URL.Scheme == "" {
		if req.TLS != nil {
			newReq.URL.Scheme = "https"
		} else {
			newReq.URL.Scheme = "http"
		}
	}
	if newReq.URL.Host == "" {
		newReq.URL.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = newReq.URL.Host
	}

	// MITM 模式：对于需要 ECH/CF pool 的站点，直接 301 升级到 HTTPS
	// 避免用直连 transport 访问被封锁的 IP（direct transport 无法用 ECH 或 CF pool IP）
	if rule.Mode == "mitm" && (rule.ECHEnabled || rule.UseCFPool) && newReq.URL.Scheme == "http" {
		httpsURL := *newReq.URL
		httpsURL.Scheme = "https"
		if httpsURL.Host == "" {
			httpsURL.Host = req.Host
		}
		http.Redirect(w, req, httpsURL.String(), http.StatusMovedPermanently)
		return
	}

	if rule.Mode == "direct" {
		// 直接转发请求
		resp, err := p.transport.RoundTrip(newReq)
		if err != nil {
			log.Printf("[HTTP] Direct proxy failed: %v", err)
			http.Error(w, "Failed to proxy", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// 复制响应头
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	if rule.Upstream != "" {
		defaultPort := "80"
		if strings.EqualFold(newReq.URL.Scheme, "https") {
			defaultPort = "443"
		}
		candidates := splitUpstreamCandidates(normalizeHost(newReq.Host), rule.Upstream, defaultPort)
		if len(candidates) > 0 {
			newReq.URL.Host = candidates[0]
		}
	}

	resp, err := p.transport.RoundTrip(newReq)
	if err != nil {
		log.Printf("[HTTP] HTTPS proxy failed: %v", err)
		http.Error(w, "Failed to proxy", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *ProxyServer) handleMITM(clientConn net.Conn, host string, rule Rule, dialCandidates []string, initialDialAddr string) {
	log.Printf("[MITM] Handling %s with SNI: %s", host, rule.SniFake)

	if p.certGenerator == nil {
		log.Printf("[MITM] No cert generator, falling back to direct")
		p.directTunnel(clientConn, clientConn)
		return
	}

	caCert := p.certGenerator.GetCACert()
	caKey := p.certGenerator.GetCAKey()
	if caCert == nil || caKey == nil {
		log.Printf("[MITM] CA cert/key not available")
		clientConn.Close()
		return
	}

	sniHost := chooseUpstreamSNI(host, rule)
	log.Printf("[MITM] Upstream handshake SNI selected: %s", sniHost)

	orderedCandidates := make([]string, 0, len(dialCandidates)+1)
	if strings.TrimSpace(initialDialAddr) != "" {
		orderedCandidates = append(orderedCandidates, initialDialAddr)
	}
	for _, c := range dialCandidates {
		if strings.TrimSpace(c) == "" || c == initialDialAddr {
			continue
		}
		orderedCandidates = append(orderedCandidates, c)
	}

	upstreamRW, upstreamProtocol, err := p.establishUpstreamConn(host, rule, orderedCandidates, "")
	if err != nil {
		log.Printf("[MITM] Failed to establish upstream: %v", err)
		clientConn.Close()
		return
	}
	defer upstreamRW.Close()

	if upstreamRW == nil {
		log.Printf("[MITM] No usable upstream")
		clientConn.Close()
		return
	}

	log.Printf("[MITM] Upstream negotiated protocol: %s", upstreamProtocol)

	cert, err := p.generateCert(host, caCert, caKey)
	if err != nil {
		log.Printf("[MITM] Failed to generate cert: %v", err)
		clientConn.Close()
		upstreamRW.Close()
		return
	}

	clientNextProtos := []string{upstreamProtocol}
	if upstreamProtocol == "" {
		clientNextProtos = []string{"http/1.1"}
	} else if upstreamProtocol == "h2" {
		clientNextProtos = []string{"h2", "http/1.1"}
	} else {
		clientNextProtos = []string{"http/1.1"}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   clientNextProtos,
	}

	clientTls := tls.Server(clientConn, tlsConfig)
	if err := clientTls.Handshake(); err != nil {
		log.Printf("[MITM] Client TLS handshake failed: %v", err)
		clientConn.Close()
		upstreamRW.Close()
		return
	}

	clientALPN := clientTls.ConnectionState().NegotiatedProtocol
	log.Printf("[MITM] Client ALPN: %s, Upstream Protocol: %s", clientALPN, upstreamProtocol)

	p.directTunnel(clientTls, upstreamRW)
}

func (p *ProxyServer) directTunnel(clientConn, upstreamConn net.Conn) {
	log.Printf("[Tunnel] Starting direct tunnel")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		n, err := io.CopyBuffer(upstreamConn, clientConn, buf)
		log.Printf("[Tunnel] Client -> Upstream: %d bytes, err: %v", n, err)
		upstreamConn.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		n, err := io.CopyBuffer(clientConn, upstreamConn, buf)
		log.Printf("[Tunnel] Upstream -> Client: %d bytes, err: %v", n, err)
		clientConn.Close()
	}()
	wg.Wait()
	log.Printf("[Tunnel] Tunnel closed")
}

func (p *ProxyServer) generateCert(host string, caCert *x509.Certificate, caKey interface{}) (*tls.Certificate, error) {
	host = normalizeHost(host)
	p.certCacheMu.RLock()
	if cert, ok := p.certCache[host]; ok && cert != nil {
		p.certCacheMu.RUnlock()
		return cert, nil
	}
	p.certCacheMu.RUnlock()

	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	p.certCacheMu.Lock()
	p.certCache[host] = &cert
	p.certCacheMu.Unlock()
	return &cert, nil
}

func (p *ProxyServer) handleTransparent(clientConn, upstreamConn net.Conn, host string, rule Rule) {
	// Transparent mode should forward raw TLS bytes without terminating TLS.
	// Terminating TLS here would require MITM on the client side as well.
	log.Printf("[Transparent] Tunneling %s -> %s (raw TCP)", host, rule.Upstream)
	p.directTunnel(clientConn, upstreamConn)
}

func (r *RuleManager) SetRules(rules []Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = rules
}

func (r *RuleManager) matchRule(host, mode string) Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	host = normalizeHost(host)
	mode = strings.ToLower(strings.TrimSpace(mode))
	
	best := Rule{}
	bestScore := -1
	for _, rule := range r.rules {
		if !rule.Enabled {
			continue
		}
		
		score := domainMatchScore(host, rule.Domain)
		if score >= 0 && score > bestScore {
			best = rule
			bestScore = score
		}
	}
	
	// 如果命中了特定规则
	if bestScore >= 0 {
		// [V2.9.4 特殊逻辑]：如果用户开启了全局“透传模式”，说明用户可能没装证书。
		// 此时如果命中了标记为 MITM 的规则，直接让它走“直连（Direct）”，而不是尝试透传或中间人，
		// 从而彻底避免因为劫持而产生的证书报错。
		if mode == "transparent" && best.Mode == "mitm" {
			log.Printf("[RuleMatch] Global Transparent detected: Downgrading MITM rule (%s) to DIRECT to avoid cert errors.", host)
			best.Mode = "direct"
		}
		return best
	}

	// 如果没有命中任何特定规则，则使用全局模式作为默认策略
	// 注意：如果全局模式是 "mitm" 或 "transparent"，则返回对应的基础 Rule
	return Rule{
		Mode:    mode,
		Enabled: true,
	}
}

func (p *ProxyServer) GetStats() (int64, int64, int64) {
	return 0, 0, 0
}

func (p *ProxyServer) trackAccepted(remote string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.recentIngress) >= 10 {
		p.recentIngress = p.recentIngress[1:]
	}
	p.recentIngress = append(p.recentIngress, remote)
}

func (p *ProxyServer) GetDiagnostics() (int64, int64, int64, []string) {
	return 0, 0, 0, nil
}

func NewRuleManager(configPath string) *RuleManager {
	return &RuleManager{
		configPath: configPath,
		rules:      []Rule{},
	}
}

func (rm *RuleManager) LoadConfig() error {
	data, err := os.ReadFile(rm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rm.saveDefaultConfig()
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	rm.siteGroups = config.SiteGroups
	rm.upstreams = config.Upstreams
	if rm.upstreams == nil {
		rm.upstreams = []Upstream{}
	}
	rm.cloudflareConfig = config.CloudflareConfig
	rm.serverHost = config.ServerHost
	rm.serverAuth = config.ServerAuth

	// Sync Cloudflare Config if ProxyServer is linked
	// Note: In current architecture, RuleManager doesn't have a back-pointer to ProxyServer.
	// ProxyServer.SetRuleManager is used. We might need to update ProxyServer's pool elsewhere.
	// But actually, ProxyServer holds the pool, so when LoadConfig is called via the RuleManager
	// inside ProxyServer, it should be updated.
	// Wait, ProxyServer has a pointer to RuleManager.

	migrated := false
	for i := range rm.siteGroups {
		rm.siteGroups[i].Website = strings.TrimSpace(rm.siteGroups[i].Website)
		if rm.siteGroups[i].Website == "" {
			rm.siteGroups[i].Website = inferWebsiteFromSiteGroup(rm.siteGroups[i])
			migrated = true
		}
	}

	rm.buildRules()
	if migrated {
		if err := rm.saveConfig(); err != nil {
			log.Printf("[Config] migrate website field failed: %v", err)
		} else {
			log.Printf("[Config] migrated website field for existing site groups")
		}
	}
	return nil
}

func (rm *RuleManager) saveDefaultConfig() error {
	siteGroups, upstreams, err := loadEmbeddedRules()
	if err != nil {
		return err
	}

	rm.siteGroups = siteGroups
	rm.upstreams = upstreams
	rm.buildRules()

	return rm.saveConfig()
}

func loadEmbeddedRules() ([]SiteGroup, []Upstream, error) {
	var siteGroups []SiteGroup
	var upstreams []Upstream

	execPath := os.Args[0]
	if filepath.IsAbs(execPath) == false {
		var err error
		execPath, err = os.Executable()
		if err != nil {
			execPath = os.Args[0]
		}
	}
	execDir := filepath.Dir(execPath)

	ruleFiles := []string{
		filepath.Join(execDir, "rules", "mitm.json"),
		filepath.Join(execDir, "rules", "transparent.json"),
	}

	log.Printf("[Config] Searching for rules in: %s", execDir)

	for _, file := range ruleFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("[Config] Cannot read rule file: %s, err: %v", file, err)
			continue
		}

		var configFile ConfigFile
		if err := json.Unmarshal(data, &configFile); err != nil {
			log.Printf("[Config] Failed to parse %s: %v", file, err)
			continue
		}

		log.Printf("[Config] Loaded rule file: %s, found %d rules", file, len(configFile.Rules))

		for _, rule := range configFile.Rules {
			sg := SiteGroup{
				ID:            generateID(),
				Name:          rule.Name,
				Website:       strings.TrimSpace(rule.Website),
				Domains:       rule.Domains,
				Mode:          configFile.Type,
				Upstream:      rule.Upstream,
				Upstreams:     append([]string(nil), rule.Upstreams...),
				SniFake:       rule.SniFake,
				ConnectPolicy: strings.ToLower(strings.TrimSpace(rule.ConnectPolicy)),
				SniPolicy:     strings.ToLower(strings.TrimSpace(rule.SniPolicy)),
				AlpnPolicy:    strings.ToLower(strings.TrimSpace(rule.AlpnPolicy)),
				UTLSPolicy:    strings.ToLower(strings.TrimSpace(rule.UTLSPolicy)),
				Enabled:       rule.Enabled,
			}
			siteGroups = append(siteGroups, sg)
		}
	}

	if len(siteGroups) == 0 {
		return nil, nil, fmt.Errorf("no embedded rules found")
	}

	// No hardcoded upstream fallback. All upstream selection must be rule-driven.
	upstreams = []Upstream{}

	log.Printf("[Config] Loaded %d rules from embedded files", len(siteGroups))
	return siteGroups, upstreams, nil
}

func (rm *RuleManager) buildRules() {
	rm.rules = []Rule{}
	upstreamMap := make(map[string]string)
	for _, up := range rm.upstreams {
		if up.Enabled && up.Address != "" {
			upstreamMap[up.ID] = up.Address
		}
	}

	for _, sg := range rm.siteGroups {
		if !sg.Enabled {
			continue
		}

		// Resolve upstream ID to actual address
		resolvedUpstream := sg.Upstream
		if addr, ok := upstreamMap[sg.Upstream]; ok {
			resolvedUpstream = addr
		}

		resolvedUpstreams := make([]string, 0, len(sg.Upstreams))
		for _, upId := range sg.Upstreams {
			if addr, ok := upstreamMap[upId]; ok {
				resolvedUpstreams = append(resolvedUpstreams, addr)
			} else {
				resolvedUpstreams = append(resolvedUpstreams, upId)
			}
		}

		for _, domain := range sg.Domains {
			rule := Rule{
				Domain:        domain,
				Mode:          sg.Mode,
				Upstream:      resolvedUpstream,
				Upstreams:     resolvedUpstreams,
				SniFake:       sg.SniFake,
				ConnectPolicy: strings.TrimSpace(sg.ConnectPolicy),
				SniPolicy:     strings.TrimSpace(sg.SniPolicy),
				AlpnPolicy:    strings.TrimSpace(sg.AlpnPolicy),
				UTLSPolicy:    strings.TrimSpace(sg.UTLSPolicy),
				Enabled:       true,
				SiteID:        sg.ID,
				ECHEnabled:    sg.ECHEnabled,
				ECHDomain:     sg.ECHDomain,
				UseCFPool:     sg.UseCFPool,
			}
			rm.rules = append(rm.rules, rule)
		}
	}
}

func (rm *RuleManager) incrementRuleHit(siteID string) {
	// No-op after stats removal
}

func (rm *RuleManager) GetRuleHitCounts() map[string]int64 {
	return map[string]int64{}
}

func (rm *RuleManager) GetSiteGroups() []SiteGroup {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.siteGroups
}

func (rm *RuleManager) GetServerHost() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.serverHost
}

func (rm *RuleManager) GetServerAuth() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.serverAuth
}

func (rm *RuleManager) UpdateServerConfig(host, auth string) error {
	rm.mu.Lock()
	rm.serverHost = host
	rm.serverAuth = auth
	rm.mu.Unlock()
	return rm.saveConfig()
}

func (rm *RuleManager) GetCloudflareConfig() CloudflareConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.cloudflareConfig
}

func (rm *RuleManager) UpdateCloudflareConfig(cfg CloudflareConfig) error {
	rm.mu.Lock()
	rm.cloudflareConfig = cfg
	rm.mu.Unlock()
	return rm.saveConfig()
}

func (rm *RuleManager) AddSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.ID = generateID()
	sg.Website = strings.TrimSpace(sg.Website)
	rm.siteGroups = append(rm.siteGroups, sg)
	rm.buildRules()
	return rm.saveConfig()
}

func (rm *RuleManager) UpdateSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.Website = strings.TrimSpace(sg.Website)
	for i, s := range rm.siteGroups {
		if s.ID == sg.ID {
			rm.siteGroups[i] = sg
			break
		}
	}
	rm.buildRules()
	return rm.saveConfig()
}

func (rm *RuleManager) DeleteSiteGroup(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, s := range rm.siteGroups {
		if s.ID == id {
			rm.siteGroups = append(rm.siteGroups[:i], rm.siteGroups[i+1:]...)
			break
		}
	}
	rm.buildRules()
	return rm.saveConfig()
}

func (rm *RuleManager) GetUpstreams() []Upstream {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.upstreams
}

func (rm *RuleManager) AddUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	u.ID = generateID()
	rm.upstreams = append(rm.upstreams, u)
	return rm.saveConfig()
}

func (rm *RuleManager) UpdateUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == u.ID {
			rm.upstreams[i] = u
			break
		}
	}
	return rm.saveConfig()
}

func (rm *RuleManager) DeleteUpstream(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == id {
			rm.upstreams = append(rm.upstreams[:i], rm.upstreams[i+1:]...)
			break
		}
	}
	return rm.saveConfig()
}

func (rm *RuleManager) saveConfig() error {
	config := Config{
		ListenPort:       "8080",
		ServerHost:       rm.serverHost,
		ServerAuth:       rm.serverAuth,
		SiteGroups:       rm.siteGroups,
		Upstreams:        rm.upstreams,
		CloudflareConfig: rm.cloudflareConfig,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(rm.configPath, data, 0644)
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (p *ProxyServer) GetUConn(conn net.Conn, sni string, allowInsecure bool, alpn string, echConfig []byte) *utls.UConn {
	nextProtos := []string{"h2", "http/1.1"}
	if strings.EqualFold(strings.TrimSpace(alpn), "http/1.1") {
		nextProtos = []string{"http/1.1"}
	}

	config := &utls.Config{
		// ECH 下这里必须是内层真实 SNI。外层公开名由 ECHConfig 的 PublicName 驱动。
		ServerName:                     sni,
		InsecureSkipVerify:             allowInsecure,
		EncryptedClientHelloConfigList: echConfig,
		NextProtos:                     nextProtos,
	}

	if allowInsecure && len(echConfig) > 0 {
		// ECH 成功后证书可能呈现 public_name 相关名称，跳过 hostname 验证避免误报。
		config.InsecureServerNameToVerify = "*"
		config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		}
	}

	clientHelloID := utls.HelloChrome_Auto
	if strings.EqualFold(strings.TrimSpace(alpn), "http/1.1") {
		clientHelloID = utls.HelloFirefox_Auto
	}
	uconn := utls.UClient(conn, config, clientHelloID)
	return uconn
}

func (p *ProxyServer) handleServerMITM(clientConn net.Conn, host string, rule Rule) {
	defer clientConn.Close()
	log.Printf("[ServerMode] Handling %s via Server", host)

	if p.certGenerator == nil {
		log.Printf("[ServerMode] No cert generator available")
		return
	}
	caCert := p.certGenerator.GetCACert()
	caKey := p.certGenerator.GetCAKey()
	cert, err := p.generateCert(host, caCert, caKey)
	if err != nil {
		log.Printf("[ServerMode] Cert error: %v", err)
		return
	}

	// 强制客户端侧使用 HTTP/1.1，避免单连接被升级为 HTTP/2 后的多路复用处理复杂化
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	}
	clientTls := tls.Server(clientConn, tlsConfig)
	if err := clientTls.Handshake(); err != nil {
		log.Printf("[ServerMode] TLS handshake failed: %v", err)
		return
	}

	serverHost := p.rules.serverHost
	if serverHost == "" {
		log.Printf("[ServerMode] ServerHost not configured")
		return
	}

	dialCandidates := []string{}
	seen := map[string]struct{}{}
	if rule.UseCFPool && p.cfPool != nil {
		topIPs := p.cfPool.GetTopIPs(5)
		for _, ip := range topIPs {
			addr := net.JoinHostPort(ip, "443")
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			dialCandidates = append(dialCandidates, addr)
		}
	}
	serverAddr := net.JoinHostPort(serverHost, "443")
	if _, ok := seen[serverAddr]; !ok {
		dialCandidates = append(dialCandidates, serverAddr)
	}

	upstreamConn, upstreamProtocol, err := p.establishUpstreamConn(serverHost, rule, dialCandidates, "http/1.1")
	if err != nil {
		log.Printf("[ServerMode] Failed to establish upstream connection: %v", err)
		return
	}
	defer upstreamConn.Close()

	log.Printf("[ServerMode] Upstream protocol: %s", upstreamProtocol)

	var uconn *utls.UConn
	if uc, ok := upstreamConn.(*utls.UConn); ok {
		uconn = uc
	}

	var transport http.RoundTripper
	if upstreamProtocol == "h2" || (uconn != nil && uconn.ConnectionState().NegotiatedProtocol == "h2") {
		cs := uconn.ConnectionState()
		peerCN := ""
		if len(cs.PeerCertificates) > 0 {
			peerCN = cs.PeerCertificates[0].Subject.CommonName
		}
		log.Printf("[ServerMode] Upstream uTLS negotiated: alpn=%s echAccepted=%v peerCN=%s", cs.NegotiatedProtocol, cs.ECHAccepted, peerCN)
		t2 := &http2.Transport{}
		c2, err := t2.NewClientConn(uconn)
		if err != nil {
			log.Printf("[ServerMode] H2 wrapper failed: %v", err)
			return
		}
		transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return c2.RoundTrip(req)
		})
	} else {
		transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return upstreamConn, nil
			},
		}
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			targetUrl := "https://" + host + req.URL.Path
			if req.URL.RawQuery != "" {
				targetUrl += "?" + req.URL.RawQuery
			}
            
			path := req.URL.EscapedPath()
			if path == "" || !strings.HasPrefix(path, "/") {
				path = "/" + strings.TrimPrefix(path, "/")
			}
			
			workerUrlStr := "https://" + serverHost + "/" + p.rules.serverAuth + "/" + host + path
			if req.URL.RawQuery != "" {
				workerUrlStr += "?" + req.URL.RawQuery
			}

			newReq, err := http.NewRequest(req.Method, workerUrlStr, req.Body)
            if err != nil {
                http.Error(w, "Bad request", http.StatusInternalServerError)
                return
            }

			for k, vv := range req.Header {
				for _, v := range vv {
					newReq.Header.Add(k, v)
				}
			}
			newReq.Host = serverHost
			log.Printf("[ServerMode] Forward request method=%s workerURL=%s host=%s target=%s contentLength=%d", req.Method, workerUrlStr, newReq.Host, targetUrl, req.ContentLength)

			hopByHop := []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}
			for _, h := range hopByHop {
				newReq.Header.Del(h)
			}

			resp, err := client.Do(newReq)
			if err != nil {
                log.Printf("[ServerMode] Forwarding error method=%s workerURL=%s host=%s target=%s err=%v", req.Method, workerUrlStr, newReq.Host, targetUrl, err)
				http.Error(w, "Proxy error", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			log.Printf("[ServerMode] Upstream response status=%d target=%s", resp.StatusCode, targetUrl)

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}),
	}
	
	_ = srv.Serve(&singleConnListener{conn: clientTls, done: make(chan struct{})})
}

// establishUpstreamConn 整合多节点拨号、优选 IP、uTLS 握手及 ECH 自动提取逻辑
func (p *ProxyServer) establishUpstreamConn(host string, rule Rule, dialCandidates []string, initialALPN string) (net.Conn, string, error) {
	// 1. 确定拨号地址
	ordered := dialCandidates
	if len(ordered) == 0 {
		ordered = []string{net.JoinHostPort(host, "443")}
	}

	// 2. 预计算握手参数（按候选逐个握手重试）
	baseDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	utlsPolicy := strings.ToLower(strings.TrimSpace(rule.UTLSPolicy))
	sniPolicy := strings.ToLower(strings.TrimSpace(rule.SniPolicy))
	sniHost := chooseUpstreamSNI(host, rule)
	effectiveFakeSNI := strings.TrimSpace(rule.SniFake) != "" || (sniPolicy == "fake" && strings.TrimSpace(sniHost) != "" && !strings.EqualFold(strings.TrimSpace(sniHost), strings.TrimSpace(host)))

	useUTLS := false
	switch utlsPolicy {
	case "off": useUTLS = false
	case "on":  useUTLS = true
	default:    useUTLS = effectiveFakeSNI || rule.ECHEnabled
	}

	upstreamALPN := initialALPN
	if upstreamALPN == "" {
		upstreamALPN = "h2_h1"
	}

	var echConfig []byte
	if useUTLS && rule.ECHEnabled && p.dohResolver != nil {
		echLookupDomain := rule.ECHDomain
		if echLookupDomain == "" {
			echLookupDomain = host
		}
		log.Printf("[Upstream] Fetching ECH for %s (via %s)", host, echLookupDomain)
		echCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		echConfig, _ = p.dohResolver.ResolveECH(echCtx, echLookupDomain)
		cancel()
		if len(echConfig) > 0 {
			log.Printf("[Upstream] ECH Hijacked/Fetched (%d bytes)", len(echConfig))
		}
	}

	// 3. 按候选逐个拨号+握手（关键：握手失败也要尝试下一个候选）
	var errs []string
	for _, addr := range ordered {
		rawConn, dialErr := baseDialer.Dial("tcp", addr)
		if dialErr != nil {
			errs = append(errs, fmt.Sprintf("%s dial: %v", addr, dialErr))
			if rule.UseCFPool && p.cfPool != nil {
				h, _, _ := net.SplitHostPort(addr)
				if h != "" {
					p.cfPool.ReportFailure(h)
				}
			}
			continue
		}

		if useUTLS {
			targetSNI := sniHost
			// [ECH 挪用专用] 如果获取到了 ECH 公钥，说明我们要开启隐身模式。
			// 此时 targetSNI 不应是业务域名，而应是 ECH 公钥的主人域名，
			// 这样握手过程中的 inner-client-hello 才能通过 cloudflare 的校验。
			if len(echConfig) > 0 {
				targetSNI = host
			}

			uconn := p.GetUConn(rawConn, targetSNI, true, upstreamALPN, echConfig)
			utlsErr := uconn.Handshake()
			if utlsErr == nil {
				cs := uconn.ConnectionState()
				peerCN := ""
				peerSAN := ""
				if len(cs.PeerCertificates) > 0 {
					peerCN = cs.PeerCertificates[0].Subject.CommonName
					if len(cs.PeerCertificates[0].DNSNames) > 0 {
						peerSAN = cs.PeerCertificates[0].DNSNames[0]
					}
				}
				log.Printf("[Upstream] uTLS handshake ok host=%s addr=%s targetSNI=%s alpn=%s echAccepted=%v peerCN=%s peerSAN0=%s", host, addr, targetSNI, cs.NegotiatedProtocol, cs.ECHAccepted, peerCN, peerSAN)
				if rule.UseCFPool && p.cfPool != nil {
					h, _, _ := net.SplitHostPort(addr)
					if h != "" {
						p.cfPool.ReportSuccess(h)
					}
				}
				return uconn, cs.NegotiatedProtocol, nil
			}
			rawConn.Close()
			errs = append(errs, fmt.Sprintf("%s utls: %v", addr, utlsErr))
			if rule.UseCFPool && p.cfPool != nil {
				h, _, _ := net.SplitHostPort(addr)
				if h != "" {
					p.cfPool.ReportFailure(h)
				}
			}
			continue
		}

		// 标准 TLS Fallback（逐候选）
		upTLSConfig := &tls.Config{
			ServerName:         sniHost,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}
		upstreamTLS := tls.Client(rawConn, upTLSConfig)
		if err := upstreamTLS.Handshake(); err != nil {
			rawConn.Close()
			errs = append(errs, fmt.Sprintf("%s tls: %v", addr, err))
			if rule.UseCFPool && p.cfPool != nil {
				h, _, _ := net.SplitHostPort(addr)
				if h != "" {
					p.cfPool.ReportFailure(h)
				}
			}
			continue
		}
		stdCS := upstreamTLS.ConnectionState()
		peerCN := ""
		if len(stdCS.PeerCertificates) > 0 {
			peerCN = stdCS.PeerCertificates[0].Subject.CommonName
		}
		log.Printf("[Upstream] std TLS handshake ok host=%s addr=%s sni=%s alpn=%s peerCN=%s", host, addr, sniHost, stdCS.NegotiatedProtocol, peerCN)
		if rule.UseCFPool && p.cfPool != nil {
			h, _, _ := net.SplitHostPort(addr)
			if h != "" {
				p.cfPool.ReportSuccess(h)
			}
		}
		return upstreamTLS, stdCS.NegotiatedProtocol, nil
	}

	if len(errs) == 0 {
		return nil, "", fmt.Errorf("all candidates failed with unknown error")
	}
	return nil, "", fmt.Errorf("all candidates failed: %s", strings.Join(errs, " | "))
}
