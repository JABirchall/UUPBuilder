package windows

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
)

type fixtureProxy struct {
	config    proxyConfig
	automatic func(string) (proxyDecision, error)
}

func (f fixtureProxy) configuration() (proxyConfig, error) { return f.config, nil }
func (f fixtureProxy) resolve(_ context.Context, target string, _ proxyConfig) (proxyDecision, error) {
	return f.automatic(target)
}

func TestSystemProxyResolvesManualAndAutomaticConfiguration(t *testing.T) {
	r := &ProxyResolver{port: fixtureProxy{config: proxyConfig{Proxy: "http=plain.example:80;https=secure.example:8080", Bypass: "<local>;*.internal;exact.example:444"}}}
	for raw, want := range map[string]string{"http://public.example/a": "http://plain.example:80", "https://public.example/b": "http://secure.example:8080", "http://printer/": "", "https://host.internal/": "", "https://exact.example:444/": ""} {
		u, _ := url.Parse(raw)
		got, err := r.Resolve(context.Background(), u)
		if err != nil || proxyText(got) != want {
			t.Errorf("%s: %v %v, want %s", raw, got, err, want)
		}
	}
	r.port = fixtureProxy{config: proxyConfig{AutoConfigURL: "http://config.example/proxy.pac"}, automatic: func(target string) (proxyDecision, error) {
		switch target {
		case "https://one.example/path":
			return proxyDecision{Proxy: "pac.example:3128"}, nil
		case "https://two.example/":
			return proxyDecision{Direct: true}, nil
		default:
			return proxyDecision{}, errors.New("wrong URL")
		}
	}}
	for raw, want := range map[string]string{"https://one.example/path": "http://pac.example:3128", "https://two.example/": ""} {
		u, _ := url.Parse(raw)
		got, err := r.Resolve(context.Background(), u)
		if err != nil || proxyText(got) != want {
			t.Errorf("PAC %s: %v %v", raw, got, err)
		}
	}
}
func proxyText(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func TestProxyFailureDoesNotSilentlyConnectDirect(t *testing.T) {
	r := &ProxyResolver{port: fixtureProxy{config: proxyConfig{AutoDetect: true}, automatic: func(string) (proxyDecision, error) { return proxyDecision{}, errors.New("PAC unavailable") }}}
	u, _ := url.Parse("https://public.example/")
	if _, err := r.Resolve(context.Background(), u); err == nil {
		t.Fatal("lost automatic proxy error")
	}
	for _, raw := range []string{"ftp://example.com/", "https://user:password@example.com/", "https:///"} {
		u, _ := url.Parse(raw)
		if _, err := r.Resolve(context.Background(), u); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestNativeProxyReadsSystemSettings(t *testing.T) {
	c, err := (nativeProxy{}).configuration()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native system settings read (manual=%t auto=%t PAC=%t)", c.Proxy != "", c.AutoDetect, c.AutoConfigURL != "")
}

func TestNativePACResolutionIsURLSpecific(t *testing.T) {
	s := httptest.NewServer(httpHandlerPAC{})
	defer s.Close()
	r := &ProxyResolver{port: nativeProxyWithConfig{proxyConfig{AutoConfigURL: s.URL + "/proxy.pac"}}}
	for raw, want := range map[string]string{"https://one.example/path": "http://127.0.0.1:3128", "https://two.example/": ""} {
		u, _ := url.Parse(raw)
		got, err := r.Resolve(context.Background(), u)
		if err != nil || proxyText(got) != want {
			t.Fatalf("native PAC %s: %v %v", raw, got, err)
		}
	}
}
