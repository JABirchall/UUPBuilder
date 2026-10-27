package windows

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type proxyConfig struct {
	AutoDetect                   bool
	AutoConfigURL, Proxy, Bypass string
}
type proxyDecision struct {
	Direct        bool
	Proxy, Bypass string
}
type proxyPort interface {
	configuration() (proxyConfig, error)
	resolve(context.Context, string, proxyConfig) (proxyDecision, error)
}
type ProxyResolver struct{ port proxyPort }

const (
	winHTTPAutoDetectionFailed syscall.Errno = 12180
	winHTTPLoginFailure        syscall.Errno = 12015
)

// NewProxyResolver uses the current user's Windows Internet settings and
// WinHTTP URL-specific PAC/WPAD decisions. It does not consult environment vars.
// No-discovery falls back to configured manual settings; required PAC errors
// are returned so callers never silently bypass a required proxy.
func NewProxyResolver() *ProxyResolver { return &ProxyResolver{port: nativeProxy{}} }

func (r *ProxyResolver) Resolve(ctx context.Context, target *url.URL) (*url.URL, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil {
		return nil, errors.New("absolute HTTP(S) target without credentials required")
	}
	p := r.port
	if p == nil {
		p = nativeProxy{}
	}
	c, err := p.configuration()
	if err != nil {
		return nil, err
	}
	if c.AutoDetect || c.AutoConfigURL != "" {
		safe := *target
		safe.Fragment = ""
		decision, err := p.resolve(ctx, safe.String(), c)
		if err != nil {
			// An optional discovery search finding no PAC is different from a
			// configured script, authentication, download or execution failure.
			if c.AutoDetect && c.AutoConfigURL == "" && errors.Is(err, winHTTPAutoDetectionFailed) {
				return selectProxy(target, c.Proxy, c.Bypass)
			}
			return nil, fmt.Errorf("system automatic proxy: %w", err)
		}
		if decision.Direct {
			return nil, nil
		}
		return selectProxy(target, decision.Proxy, decision.Bypass)
	}
	return selectProxy(target, c.Proxy, c.Bypass)
}

func selectProxy(target *url.URL, proxies, bypass string) (*url.URL, error) {
	if bypasses(target, bypass) {
		return nil, nil
	}
	var fallback, selected string
	for _, part := range strings.FieldsFunc(proxies, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
		scheme, address, qualified := strings.Cut(part, "=")
		if qualified {
			if strings.EqualFold(scheme, target.Scheme) && selected == "" {
				selected = address
			}
		} else if fallback == "" {
			fallback = part
		}
	}
	if selected == "" {
		selected = fallback
	}
	if selected == "" {
		return nil, nil
	}
	if !strings.Contains(selected, "://") {
		selected = "http://" + selected
	}
	u, err := url.Parse(selected)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return nil, errors.New("invalid system proxy origin")
	}
	return u, nil
}

func bypasses(u *url.URL, list string) bool {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	for _, pattern := range strings.FieldsFunc(strings.ToLower(list), func(r rune) bool { return r == ';' || r == ' ' || r == '\t' }) {
		if pattern == "<local>" {
			if !strings.Contains(host, ".") && net.ParseIP(host) == nil {
				return true
			}
			continue
		}
		pattern = strings.TrimPrefix(strings.TrimPrefix(pattern, "http://"), "https://")
		patternHost, patternPort := pattern, ""
		if h, p, err := net.SplitHostPort(pattern); err == nil {
			patternHost, patternPort = h, p
		} else if strings.HasPrefix(pattern, "[") && strings.HasSuffix(pattern, "]") {
			patternHost = pattern[1 : len(pattern)-1]
		}
		if patternPort != "" && patternPort != port {
			continue
		}
		// Compare literal addresses before considering wildcard syntax. IPv6
		// brackets delimit an address; they are never a glob character class.
		if ip := net.ParseIP(patternHost); ip != nil {
			if candidate := net.ParseIP(host); candidate != nil && ip.Equal(candidate) {
				return true
			}
			continue
		}
		if !strings.ContainsAny(patternHost, "*?") {
			if patternHost == host {
				return true
			}
			continue
		}
		if strings.ContainsAny(patternHost, "[]") {
			continue
		}
		if match, _ := path.Match(patternHost, host); match {
			return true
		}
	}
	return false
}

type nativeProxy struct{}

var winHTTP = windows.NewLazySystemDLL("winhttp.dll")
var winHTTPOpen = winHTTP.NewProc("WinHttpOpen")
var winHTTPClose = winHTTP.NewProc("WinHttpCloseHandle")
var winHTTPGetIE = winHTTP.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
var winHTTPGetDefault = winHTTP.NewProc("WinHttpGetDefaultProxyConfiguration")
var winHTTPGetProxy = winHTTP.NewProc("WinHttpGetProxyForUrl")
var winHTTPTimeouts = winHTTP.NewProc("WinHttpSetTimeouts")

func freeGlobal(p *uint16) {
	if p != nil {
		windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree").Call(uintptr(unsafe.Pointer(p)))
	}
}

func (nativeProxy) configuration() (proxyConfig, error) {
	type ieConfig struct {
		AutoDetect                   int32
		AutoConfigURL, Proxy, Bypass *uint16
	}
	var c ieConfig
	ok, _, err := winHTTPGetIE.Call(uintptr(unsafe.Pointer(&c)))
	defer freeGlobal(c.AutoConfigURL)
	defer freeGlobal(c.Proxy)
	defer freeGlobal(c.Bypass)
	if ok != 0 {
		return proxyConfig{AutoDetect: c.AutoDetect != 0, AutoConfigURL: windows.UTF16PtrToString(c.AutoConfigURL), Proxy: windows.UTF16PtrToString(c.Proxy), Bypass: windows.UTF16PtrToString(c.Bypass)}, nil
	}
	var p nativeProxyInfo
	ok, _, fallbackErr := winHTTPGetDefault.Call(uintptr(unsafe.Pointer(&p)))
	defer freeGlobal(p.Proxy)
	defer freeGlobal(p.Bypass)
	if ok == 0 {
		return proxyConfig{}, fmt.Errorf("current user: %v; machine: %w", err, fallbackErr)
	}
	return proxyConfig{Proxy: windows.UTF16PtrToString(p.Proxy), Bypass: windows.UTF16PtrToString(p.Bypass)}, nil
}

type nativeProxyInfo struct {
	AccessType    uint32
	Proxy, Bypass *uint16
}

type nativeAutoProxyOptions struct {
	Flags           uint32
	AutoDetectFlags uint32
	AutoConfigURL   *uint16
	Reserved        uintptr
	ReservedDWORD   uint32
	AutoLogon       int32
}

func (nativeProxy) resolve(ctx context.Context, target string, c proxyConfig) (proxyDecision, error) {
	if err := ctx.Err(); err != nil {
		return proxyDecision{}, err
	}
	// WinHttpGetProxyForUrl is synchronous. Keep its session and all pointer data
	// owned by the resolver goroutine until it returns; cancellation never frees
	// a handle concurrently with a native call. Native timeouts bound network IO.
	type result struct {
		d   proxyDecision
		err error
	}
	done := make(chan result, 1)
	go func() { d, err := resolveNativeProxy(target, c); done <- result{d, err} }()
	select {
	case r := <-done:
		return r.d, r.err
	case <-ctx.Done():
		return proxyDecision{}, ctx.Err()
	}
}

func resolveNativeProxy(target string, c proxyConfig) (proxyDecision, error) {
	agent, _ := windows.UTF16PtrFromString("UUPBuilder/1")
	h, _, err := winHTTPOpen.Call(uintptr(unsafe.Pointer(agent)), 1, 0, 0, 0)
	if h == 0 {
		return proxyDecision{}, err
	}
	defer winHTTPClose.Call(h)
	if ok, _, err := winHTTPTimeouts.Call(h, 5000, 5000, 5000, 5000); ok == 0 {
		return proxyDecision{}, err
	}
	return resolveAutoProxyOptions(target, c, func(u *uint16, options *nativeAutoProxyOptions) (proxyDecision, error) {
		return nativeProxyLookup(h, u, options)
	})
}

func resolveAutoProxyOptions(target string, c proxyConfig, lookup func(*uint16, *nativeAutoProxyOptions) (proxyDecision, error)) (proxyDecision, error) {
	var options nativeAutoProxyOptions
	var err error
	if c.AutoDetect {
		options.Flags |= 1
		options.AutoDetectFlags = 3
	}
	if c.AutoConfigURL != "" {
		options.Flags |= 2
		options.AutoConfigURL, err = windows.UTF16PtrFromString(c.AutoConfigURL)
		if err != nil {
			return proxyDecision{}, err
		}
	}
	u, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return proxyDecision{}, err
	}
	decision, err := lookup(u, &options)
	// Keep the cacheable unauthenticated attempt first. Only a native PAC
	// login challenge enables NTLM/Negotiate using the signed-in OS identity,
	// once; no credential strings are obtained or added to product DTOs.
	if errors.Is(err, winHTTPLoginFailure) {
		options.AutoLogon = 1
		decision, err = lookup(u, &options)
	}
	runtime.KeepAlive(options)
	runtime.KeepAlive(u)
	return decision, err
}

func nativeProxyLookup(h uintptr, u *uint16, options *nativeAutoProxyOptions) (proxyDecision, error) {
	var info nativeProxyInfo
	ok, _, callErr := winHTTPGetProxy.Call(h, uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(options)), uintptr(unsafe.Pointer(&info)))
	defer freeGlobal(info.Proxy)
	defer freeGlobal(info.Bypass)
	if ok == 0 {
		return proxyDecision{}, callErr
	}
	if info.AccessType == 1 {
		return proxyDecision{Direct: true}, nil
	}
	if info.AccessType != 3 || info.Proxy == nil {
		return proxyDecision{}, errors.New("unsupported native proxy decision")
	}
	return proxyDecision{Proxy: windows.UTF16PtrToString(info.Proxy), Bypass: windows.UTF16PtrToString(info.Bypass)}, nil
}
