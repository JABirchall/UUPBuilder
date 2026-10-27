//go:build windows

package download

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"uupbuilder/internal/model"
)

func TestProxyDirectExplicitAndSystemDirectDecision(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) }))
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "origin.invalid:4567" {
			t.Error("explicit proxy lost origin")
		}
		w.Write(fixture)
	}))
	defer proxy.Close()
	for _, mode := range []model.ProxyMode{model.ProxyDirect, model.ProxyExplicit, model.ProxySystem} {
		t.Run(string(mode), func(t *testing.T) {
			opts := testOptions(t)
			opts.Proxy.Mode = mode
			var unexpected atomic.Int32
			opts.Transport = &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
				unexpected.Add(1)
				return nil, errors.New("caller transport proxy must be replaced")
			}}
			target := origin.URL
			if mode == model.ProxyExplicit {
				opts.Proxy.URL = proxy.URL
				target = "http://origin.invalid:4567/payload"
			}
			var resolved atomic.Int32
			opts.SystemProxy = proxyResolverFunc(func(ctx context.Context, u *url.URL) (*url.URL, error) {
				resolved.Add(1)
				if u.String() != target {
					t.Error("system direct decision resolved wrong URL")
				}
				return nil, nil
			})
			m := manager(t, opts)
			p := payload(t, fixture, "p.bin")
			got, err := m.FetchOne(context.Background(), p, Locator{URL: target}, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertFile(t, got, p, fixture)
			if unexpected.Load() != 0 {
				t.Fatal("caller proxy/environment policy leaked into selected mode")
			}
			want := int32(0)
			if mode == model.ProxySystem {
				want = 1
			}
			if resolved.Load() != want {
				t.Fatal("wrong proxy mode resolver used")
			}
		})
	}
}

func TestSystemProxyFailureDoesNotBypassRequiredProxy(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write(fixture) }))
	defer srv.Close()
	opts := testOptions(t)
	opts.Retries = 0
	opts.Proxy.Mode = model.ProxySystem
	opts.SystemProxy = proxyResolverFunc(func(context.Context, *url.URL) (*url.URL, error) { return nil, errors.New("runtime proxy detail") })
	m := manager(t, opts)
	_, err := m.FetchOne(context.Background(), payload(t, fixture, "p.bin"), Locator{URL: srv.URL}, nil)
	if !errors.Is(err, ErrTransfer) || requests.Load() != 0 {
		t.Fatalf("required proxy failure bypassed: %v requests=%d", err, requests.Load())
	}
}

func TestExplicitProxyRejectsCredentialsAndNonOrigins(t *testing.T) {
	for _, raw := range []string{"http://user:private@proxy.invalid", "http://proxy.invalid/path", "http://proxy.invalid/?private=secret", "ftp://proxy.invalid", "http://proxy.invalid/#fragment"} {
		opts := testOptions(t)
		opts.Proxy = model.ProxySettings{Mode: model.ProxyExplicit, URL: raw}
		m, err := NewManager(opts)
		if err != ErrInvalidOptions {
			if m != nil {
				m.Close()
			}
			t.Fatalf("invalid proxy accepted: %v", err)
		}
	}
}
