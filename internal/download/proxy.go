//go:build windows

package download

import (
	"context"
	"net/http"
	"net/url"

	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

func validURL(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil
}

func configuredTransport(opts Options) (*http.Transport, error) {
	var t *http.Transport
	if opts.Transport != nil {
		t = opts.Transport.Clone()
	} else {
		t = http.DefaultTransport.(*http.Transport).Clone()
	}
	t.DisableCompression = true
	mode := opts.Proxy.Mode
	if mode == "" {
		mode = model.ProxySystem
	}
	if mode != model.ProxyExplicit && opts.Proxy.URL != "" {
		return nil, ErrInvalidOptions
	}
	switch mode {
	case model.ProxyDirect:
		t.Proxy = nil
	case model.ProxyExplicit:
		u, err := url.Parse(opts.Proxy.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			return nil, ErrInvalidOptions
		}
		t.Proxy = http.ProxyURL(u)
	case model.ProxySystem:
		r := opts.SystemProxy
		if r == nil {
			r = windows.NewProxyResolver()
		}
		t.Proxy = func(req *http.Request) (*url.URL, error) {
			proxy, err := r.Resolve(req.Context(), req.URL)
			if err != nil {
				return nil, ErrTransfer
			}
			return proxy, nil
		}
	default:
		return nil, ErrInvalidOptions
	}
	return t, nil
}

func (m *Manager) request(ctx context.Context, locator Locator, offset int64) (*http.Response, error) {
	u, err := url.Parse(locator.URL)
	if err != nil || !validURL(u) || offset < 0 {
		return nil, ErrInvalidInput
	}
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrInvalidInput
	}
	req.Header.Set("Accept-Encoding", "identity")
	if offset > 0 {
		req.Header.Set("Range", rangeHeader(offset))
	}
	resp, err := m.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrTransfer
	}
	return resp, nil
}
