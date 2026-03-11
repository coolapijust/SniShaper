package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"snishaper/cert"
	"snishaper/proxy"
	"snishaper/sysproxy"
)

type App struct {
	ctx         context.Context
	proxyServer *proxy.ProxyServer
	certManager *cert.CertManager
	ruleManager *proxy.RuleManager
	certPath    string
	logPath     string
	logFile     *os.File
	logBuffer   *ringLogWriter
}

type ringLogWriter struct {
	mu      sync.Mutex
	lines   []string
	pending string
	max     int
}

func newRingLogWriter(max int) *ringLogWriter {
	if max <= 0 {
		max = 1000
	}
	return &ringLogWriter{
		lines: make([]string, 0, max),
		max:   max,
	}
}

func (w *ringLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	text := w.pending + strings.ReplaceAll(string(p), "\r\n", "\n")
	parts := strings.Split(text, "\n")
	if len(parts) == 0 {
		return len(p), nil
	}
	w.pending = parts[len(parts)-1]
	for _, line := range parts[:len(parts)-1] {
		if line == "" {
			continue
		}
		w.lines = append(w.lines, line)
		if len(w.lines) > w.max {
			w.lines = w.lines[len(w.lines)-w.max:]
		}
	}
	return len(p), nil
}

func (w *ringLogWriter) Snapshot(limit int) []string {
	if limit <= 0 {
		limit = 200
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	total := len(w.lines)
	if total == 0 {
		return []string{}
	}
	if limit > total {
		limit = total
	}
	start := total - limit
	out := make([]string, limit)
	copy(out, w.lines[start:])
	return out
}

func (w *ringLogWriter) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = w.lines[:0]
	w.pending = ""
}

func (w *ringLogWriter) AppendLine(line string) {
	if line == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, line)
	if len(w.lines) > w.max {
		w.lines = w.lines[len(w.lines)-w.max:]
	}
}

func NewApp() *App {
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	configPath := filepath.Join(execDir, "config.json")

	return &App{
		proxyServer: proxy.NewProxyServer("127.0.0.1:8080"),
		ruleManager: proxy.NewRuleManager(configPath),
		certPath:    filepath.Join(execDir, "cert"),
		logPath:     filepath.Join(execDir, "snishaper.log"),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.setupFileLogger()
	log.Printf("[startup] SniShaper startup hook entered")
	a.appendLog("[startup] in-memory log channel ready")
	runtime.LogInfo(ctx, "[startup] SniShaper starting...")

	var err error
	a.certManager, err = cert.InitCertManager(a.certPath)
	if err != nil {
		runtime.LogError(ctx, "[startup] Failed to init cert manager: "+err.Error())
	} else {
		runtime.LogInfo(ctx, "[startup] Cert path: "+a.certPath)
	}

	if err := a.ruleManager.LoadConfig(); err != nil {
		runtime.LogError(ctx, "[startup] Failed to load config: "+err.Error())
	}

	a.proxyServer.SetRuleManager(a.ruleManager)
	a.proxyServer.UpdateCloudflareConfig(a.ruleManager.GetCloudflareConfig())
	a.proxyServer.SetCertGenerator(a.certManager)

	if err := sysproxy.SaveOriginalProxySettings(); err != nil {
		runtime.LogWarning(ctx, "[startup] Failed to save original proxy settings: "+err.Error())
	}

	runtime.LogInfo(ctx, "[startup] SniShaper started successfully")

	// Auto-start proxy for easier diagnostics and better UX
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = a.StartProxy()

		// If auto update is enabled, fetch IPs immediately
		cfg := a.ruleManager.GetCloudflareConfig()
		if cfg.AutoUpdate {
			a.appendLog("[Cloudflare] Auto update is enabled, fetching initial IPs...")
			go a.RefreshCloudflareIPPool()
		}
	}()
}

func (a *App) shutdown(ctx context.Context) {
	runtime.LogInfo(ctx, "[shutdown] SniShaper shutting down...")

	if a.proxyServer.IsRunning() {
		runtime.LogInfo(ctx, "[shutdown] Stopping proxy server...")
		if err := a.proxyServer.Stop(); err != nil {
			runtime.LogError(ctx, "[shutdown] Failed to stop proxy: "+err.Error())
		}
	}

	runtime.LogInfo(ctx, "[shutdown] Restoring original system proxy settings...")
	if err := sysproxy.RestoreOriginalProxySettings(); err != nil {
		runtime.LogError(ctx, "[shutdown] Failed to restore proxy settings: "+err.Error())
	}

	runtime.LogInfo(ctx, "[shutdown] SniShaper shutdown complete")
	if a.logFile != nil {
		_ = a.logFile.Close()
		a.logFile = nil
	}
}

func (a *App) setupFileLogger() {
	if a.logBuffer == nil {
		a.logBuffer = newRingLogWriter(5000)
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(io.MultiWriter(os.Stdout, a.logBuffer))
	a.appendLog("[startup] logger configured (in-memory only)")
}

func (a *App) appendLog(message string) {
	if a.logBuffer == nil {
		a.logBuffer = newRingLogWriter(5000)
	}
	a.logBuffer.AppendLine(message)
}

func (a *App) GetRecentLogs(limit int) string {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	if a.logBuffer != nil {
		lines := a.logBuffer.Snapshot(limit)
		if len(lines) > 0 {
			return strings.Join(lines, "\n")
		}
	}

	a.appendLog("[diag] GetRecentLogs fallback to file-read path")

	data, err := os.ReadFile(a.logPath)
	if err != nil {
		return ""
	}

	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return strings.Join(lines, "\n")
}

func (a *App) ClearLogs() error {
	if a.logBuffer != nil {
		a.logBuffer.Clear()
	}
	a.setupFileLogger()
	return nil
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) StartProxy() error {
	runtime.LogInfo(a.ctx, "Starting proxy server...")
	a.appendLog("[action] StartProxy called")
	err := a.proxyServer.Start()
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "Only one usage of each socket address") || strings.Contains(msg, "bind: address already in use") {
			msg += " (端口被占用，请检查是否有旧版程序未关闭)"
		}
		a.appendLog("[error] StartProxy failed: " + msg)
		return fmt.Errorf(msg)
	}
	addr := a.proxyServer.GetListenAddr()
	if err := a.waitForProxyListen(addr, 2*time.Second); err != nil {
		_ = a.proxyServer.Stop()
		a.appendLog("[error] StartProxy self-check failed: " + err.Error())
		return fmt.Errorf("proxy started but not listening on %s: %w", addr, err)
	}
	a.appendLog("[action] StartProxy success")
	return nil
}

func (a *App) StopProxy() error {
	runtime.LogInfo(a.ctx, "Stopping proxy server...")
	a.appendLog("[action] StopProxy called")
	err := a.proxyServer.Stop()
	if err != nil {
		a.appendLog("[error] StopProxy failed: " + err.Error())
		return err
	}
	a.appendLog("[action] StopProxy success")
	return nil
}

func (a *App) IsProxyRunning() bool {
	return a.proxyServer.IsRunning()
}

func (a *App) GetStats() (int64, int64, int64) {
	return a.proxyServer.GetStats()
}

func (a *App) GetListenPort() int {
	addr := a.proxyServer.GetListenAddr()
	var port int
	fmt.Sscanf(addr, "127.0.0.1:%d", &port)
	return port
}

func (a *App) SetListenPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	return a.proxyServer.SetListenAddr(addr)
}

func (a *App) SetProxyMode(mode string) error {
	runtime.LogInfo(a.ctx, "[mode] Set proxy mode: "+mode)
	a.appendLog("[action] SetProxyMode: " + mode)
	err := a.proxyServer.SetMode(mode)
	if err != nil {
		a.appendLog("[error] SetProxyMode failed: " + err.Error())
	}
	return err
}

func (a *App) GetProxyMode() string {
	return a.proxyServer.GetMode()
}

func (a *App) GetCACertPath() string {
	if a.certManager != nil {
		return a.certManager.GetCACertPath()
	}
	return ""
}

type CAInstallStatus struct {
	Installed   bool
	Platform    string
	CertPath    string
	InstallHelp string
}

func (a *App) GetCAInstallStatus() CAInstallStatus {
	if a.certManager == nil {
		return CAInstallStatus{
			CertPath:    "",
			Platform:    "windows",
			InstallHelp: "证书管理器未初始化",
		}
	}
	status := a.certManager.GetCAInstallStatus()
	return CAInstallStatus{
		Installed:   status.Installed,
		Platform:    status.Platform,
		CertPath:    status.CertPath,
		InstallHelp: status.InstallHelp,
	}
}

func (a *App) OpenCAFile() error {
	if a.certManager == nil {
		return fmt.Errorf("cert manager not initialized")
	}
	return a.certManager.OpenCAFile()
}

func (a *App) GetCACertPEM() string {
	if a.certManager != nil {
		return a.certManager.GetCACertPEM()
	}
	return ""
}

func (a *App) RegenerateCert() error {
	if a.certManager == nil {
		return fmt.Errorf("cert manager not initialized")
	}
	return a.certManager.RegenerateCA()
}

func (a *App) ExportCert() string {
	if a.certManager == nil {
		return ""
	}
	data, err := a.certManager.ExportCert()
	if err != nil {
		runtime.LogError(a.ctx, "Export cert error: "+err.Error())
		return ""
	}
	return string(data)
}

func (a *App) GetSiteGroups() []proxy.SiteGroup {
	return a.ruleManager.GetSiteGroups()
}

func (a *App) AddSiteGroup(sg proxy.SiteGroup) error {
	return a.ruleManager.AddSiteGroup(sg)
}

func (a *App) UpdateSiteGroup(sg proxy.SiteGroup) error {
	return a.ruleManager.UpdateSiteGroup(sg)
}

func (a *App) DeleteSiteGroup(id string) error {
	return a.ruleManager.DeleteSiteGroup(id)
}

func (a *App) GetUpstreams() []proxy.Upstream {
	return a.ruleManager.GetUpstreams()
}

func (a *App) AddUpstream(u proxy.Upstream) error {
	return a.ruleManager.AddUpstream(u)
}

func (a *App) UpdateUpstream(u proxy.Upstream) error {
	return a.ruleManager.UpdateUpstream(u)
}

func (a *App) DeleteUpstream(id string) error {
	return a.ruleManager.DeleteUpstream(id)
}

func (a *App) GetCloudflareConfig() proxy.CloudflareConfig {
	return a.ruleManager.GetCloudflareConfig()
}

func (a *App) GetServerConfig() map[string]string {
	res := map[string]string{
		"host": "",
		"auth": "",
	}
	if a.ruleManager != nil {
		res["host"] = a.ruleManager.GetServerHost()
		res["auth"] = a.ruleManager.GetServerAuth()
	}
	return res
}

func (a *App) UpdateServerConfig(host, auth string) error {
	if a.ruleManager != nil {
		err := a.ruleManager.UpdateServerConfig(strings.TrimSpace(host), strings.TrimSpace(auth))
		if err == nil {
			a.appendLog(fmt.Sprintf("[INFO] Updated Server Worker settings, Host: %s", host))
		} else {
			a.appendLog(fmt.Sprintf("[ERROR] Failed to save Server settings: %v", err))
		}
		return err
	}
	return fmt.Errorf("RuleManager not initialized")
}

func (a *App) UpdateCloudflareConfig(cfg proxy.CloudflareConfig) error {
	// Get old config to check if AutoUpdate was toggled
	oldCfg := a.ruleManager.GetCloudflareConfig()

	err := a.ruleManager.UpdateCloudflareConfig(cfg)
	if err == nil {
		a.proxyServer.UpdateCloudflareConfig(cfg)
		// If toggled from false to true, trigger an update
		if cfg.AutoUpdate && !oldCfg.AutoUpdate {
			a.appendLog("[Cloudflare] Auto update enabled, triggering fetch...")
			go a.RefreshCloudflareIPPool()
		}
	}
	return err
}

func (a *App) RefreshCloudflareIPPool() {
	cfg := a.ruleManager.GetCloudflareConfig()
	ips, err := proxy.FetchCloudflareIPs(cfg.APIKey)
	if err != nil {
		log.Printf("[Cloudflare] Failed to fetch preferred IPs: %v", err)
		a.appendLog("[error] Cloudflare 优选 IP 获取失败: " + err.Error())
		return
	}

	if len(ips) > 0 {
		log.Printf("[Cloudflare] Successfully fetched %d preferred IPs", len(ips))
		a.appendLog(fmt.Sprintf("[success] 成功获取 %d 个 Cloudflare 优选 IP", len(ips)))

		a.proxyServer.UpdateCloudflareIPPool(ips)
		// 持久化：同步到配置文件
		cfg.PreferredIPs = ips
		_ = a.ruleManager.UpdateCloudflareConfig(cfg)
	}
}

func (a *App) ForceFetchCloudflareIPs() error {
	cfg := a.ruleManager.GetCloudflareConfig()
	ips, err := proxy.FetchCloudflareIPs(cfg.APIKey)
	if err != nil {
		log.Printf("[Cloudflare] Failed to fetch preferred IPs: %v", err)
		a.appendLog("[error] 手动获取失败: " + err.Error())
		return err
	}

	if len(ips) > 0 {
		log.Printf("[Cloudflare] Successfully fetched %d preferred IPs", len(ips))
		a.appendLog(fmt.Sprintf("[success] 成功获取 %d 个 Cloudflare 优选 IP", len(ips)))
		a.proxyServer.UpdateCloudflareIPPool(ips)
		// 持久化：同步到配置文件
		cfg.PreferredIPs = ips
		_ = a.ruleManager.UpdateCloudflareConfig(cfg)
		// Trigger immediate health check to update stats
		a.proxyServer.TriggerCFHealthCheck()
	}
	return nil
}

func (a *App) GetCloudflareIPStats() []*proxy.IPStats {
	return a.proxyServer.GetAllCFIPsWithStats()
}

func (a *App) ExportConfig() (string, error) {
	return a.ruleManager.ExportConfig()
}

func (a *App) ImportConfig(content string) error {
	return a.ruleManager.ImportConfig(content)
}

func (a *App) ImportConfigWithSummary(content string) (proxy.ImportSummary, error) {
	return a.ruleManager.ImportConfigWithSummary(content)
}

type SystemProxyStatus struct {
	Enabled  bool
	Server   string
	Override string
}

type ProxyDiagnostics struct {
	Accepted      int64
	Requests      int64
	Connects      int64
	RecentIngress []string
}

func (a *App) TriggerCFHealthCheck() {
	a.proxyServer.TriggerCFHealthCheck()
	a.appendLog("[Cloudflare] 手动触发 IP 健康检查...")
}

func (a *App) RemoveInvalidCFIPs() int {
	count := a.proxyServer.RemoveInvalidCFIPs()
	a.appendLog(fmt.Sprintf("[Cloudflare] 已清理 %d 个失效 IP", count))
	return count
}

func (a *App) GetSystemProxyStatus() SystemProxyStatus {
	status := sysproxy.GetSystemProxyStatus()
	return SystemProxyStatus{
		Enabled:  status.Enabled,
		Server:   status.Server,
		Override: status.Override,
	}
}

func (a *App) EnableSystemProxy() error {
	runtime.LogInfo(a.ctx, "[sysproxy] Enabling system proxy...")
	a.appendLog("[action] EnableSystemProxy called")
	addr := a.proxyServer.GetListenAddr()
	var port int
	fmt.Sscanf(addr, "127.0.0.1:%d", &port)
	if port == 0 {
		port = 8080
	}
	if err := a.waitForProxyListen(addr, 1200*time.Millisecond); err != nil {
		a.appendLog("[error] EnableSystemProxy blocked: proxy not listening on " + addr)
		return fmt.Errorf("proxy is not listening on %s", addr)
	}
	runtime.LogInfo(a.ctx, fmt.Sprintf("[sysproxy] Using port %d", port))
	err := sysproxy.EnableSystemProxy(port)
	if err != nil {
		a.appendLog("[error] EnableSystemProxy failed: " + err.Error())
		return err
	}
	a.appendLog(fmt.Sprintf("[action] EnableSystemProxy success: 127.0.0.1:%d", port))
	return nil
}

func (a *App) DisableSystemProxy() error {
	runtime.LogInfo(a.ctx, "[sysproxy] Disabling system proxy...")
	a.appendLog("[action] DisableSystemProxy called")
	err := sysproxy.DisableSystemProxy()
	if err != nil {
		a.appendLog("[error] DisableSystemProxy failed: " + err.Error())
		return err
	}
	a.appendLog("[action] DisableSystemProxy success")
	return nil
}

func (a *App) waitForProxyListen(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(80 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return lastErr
}

func (a *App) GetProxyDiagnostics() map[string]interface{} {
	return map[string]interface{}{
		"ListenAddr": a.proxyServer.GetListenAddr(),
		"Status":     "OK",
	}
}

func (a *App) ProxySelfCheck() string {
	addr := a.proxyServer.GetListenAddr()
	a.appendLog("[diag] ProxySelfCheck started via " + addr)

	if !a.proxyServer.IsRunning() {
		msg := "[diag] ProxySelfCheck failed: proxy not running"
		a.appendLog(msg)
		return msg
	}

	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		msg := "[diag] ProxySelfCheck failed: invalid proxy addr: " + err.Error()
		a.appendLog(msg)
		return msg
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		msg := "[diag] ProxySelfCheck failed: " + err.Error()
		a.appendLog(msg)
		return msg
	}

	resp, err := client.Do(req)
	if err != nil {
		msg := "[diag] ProxySelfCheck failed: " + err.Error()
		a.appendLog(msg)
		return msg
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))

	msg := fmt.Sprintf("[diag] ProxySelfCheck success: status=%d", resp.StatusCode)
	a.appendLog(msg)
	return msg
}
