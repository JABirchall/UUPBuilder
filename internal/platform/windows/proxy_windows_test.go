package windows

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
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

func TestSystemProxyFallsBackWhenWPADHasNoConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name         string
		config       proxyConfig
		target, want string
	}{
		{"manual HTTPS", proxyConfig{AutoDetect: true, Proxy: "http=plain.example:80;https=manual.example:8080"}, "https://public.example/path", "http://manual.example:8080"},
		{"manual bypass", proxyConfig{AutoDetect: true, Proxy: "https=manual.example:8080", Bypass: "*.internal"}, "https://host.internal/path", ""},
		{"automatic only direct", proxyConfig{AutoDetect: true}, "https://public.example/path", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &ProxyResolver{port: fixtureProxy{config: tc.config, automatic: func(string) (proxyDecision, error) {
				return proxyDecision{}, fmt.Errorf("native discovery: %w", syscall.Errno(12180))
			}}}
			u, _ := url.Parse(tc.target)
			got, err := r.Resolve(context.Background(), u)
			if err != nil || proxyText(got) != tc.want {
				t.Fatalf("got %v %v, want %s", got, err, tc.want)
			}
		})
	}
}

func TestSystemProxyDoesNotFallbackFromRequiredPACFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		config    proxyConfig
		nativeErr error
	}{
		{"configured script discovery error", proxyConfig{AutoDetect: true, AutoConfigURL: "https://config.example/proxy.pac", Proxy: "manual.example:8080"}, syscall.Errno(12180)},
		{"script only discovery error", proxyConfig{AutoConfigURL: "https://config.example/proxy.pac", Proxy: "manual.example:8080"}, syscall.Errno(12180)},
		{"authentication", proxyConfig{AutoDetect: true, Proxy: "manual.example:8080"}, syscall.Errno(12015)},
		{"malformed script", proxyConfig{AutoDetect: true, Proxy: "manual.example:8080"}, syscall.Errno(12166)},
		{"script download", proxyConfig{AutoDetect: true, Proxy: "manual.example:8080"}, syscall.Errno(12167)},
		{"cancelled", proxyConfig{AutoDetect: true, Proxy: "manual.example:8080"}, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &ProxyResolver{port: fixtureProxy{config: tc.config, automatic: func(string) (proxyDecision, error) { return proxyDecision{}, tc.nativeErr }}}
			u, _ := url.Parse("https://public.example/")
			_, err := r.Resolve(context.Background(), u)
			if !errors.Is(err, tc.nativeErr) {
				t.Fatalf("lost required PAC failure: %v", err)
			}
		})
	}
}

func TestSystemProxyMatchesLiteralIPv6BypassAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, target, bypass string
		direct               bool
	}{
		{"unbracketed", "https://[fd00::1234]/", "fd00::1234", true},
		{"bracketed", "https://[fd00::1234]/", "[fd00::1234]", true},
		{"same address expanded", "https://[FD00:0:0:0:0:0:0:1234]/", "fd00::1234", true},
		{"any port", "https://[fd00::1234]:8443/", "[fd00::1234]", true},
		{"explicit port", "https://[fd00::1234]:8443/", "[fd00::1234]:8443", true},
		{"implicit HTTPS port", "https://[fd00::1234]/", "[fd00::1234]:443", true},
		{"implicit HTTP port", "http://[fd00::1234]/", "[fd00::1234]:80", true},
		{"wrong port", "https://[fd00::1234]:8443/", "[fd00::1234]:443", false},
		{"other address", "https://[fd00::1235]/", "fd00::1234", false},
		{"brackets are not character class", "https://f/", "[fd00::1234]", false},
		{"literal hostname with port", "https://exact.example/", "exact.example:443", true},
		{"IPv4 literal with port", "https://192.0.2.5:8443/", "192.0.2.5:8443", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &ProxyResolver{port: fixtureProxy{config: proxyConfig{Proxy: "manual.example:8080", Bypass: tc.bypass}}}
			u, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.Resolve(context.Background(), u)
			want := "http://manual.example:8080"
			if tc.direct {
				want = ""
			}
			if err != nil || proxyText(got) != want {
				t.Fatalf("target %s bypass %s: %v %v, want %q", tc.target, tc.bypass, got, err, want)
			}
		})
	}
}

func TestNativePACRetriesLoginFailureWithOSCredentials(t *testing.T) {
	var attempts []int32
	c := proxyConfig{AutoDetect: true, AutoConfigURL: "https://config.example/proxy.pac"}
	decision, err := resolveAutoProxyOptions("https://target.example/path", c, func(target *uint16, options *nativeAutoProxyOptions) (proxyDecision, error) {
		attempts = append(attempts, options.AutoLogon)
		if windows.UTF16PtrToString(target) != "https://target.example/path" || windows.UTF16PtrToString(options.AutoConfigURL) != "https://config.example/proxy.pac" || options.Flags != 3 || options.AutoDetectFlags != 3 || options.Reserved != 0 || options.ReservedDWORD != 0 {
			t.Fatalf("changed native request/options %#v", options)
		}
		if options.AutoLogon == 0 {
			return proxyDecision{}, fmt.Errorf("native PAC challenge: %w", syscall.Errno(12015))
		}
		return proxyDecision{Proxy: "authenticated.example:3128"}, nil
	})
	if err != nil || decision.Proxy != "authenticated.example:3128" || !reflect.DeepEqual(attempts, []int32{0, 1}) {
		t.Fatalf("decision %#v error %v auth attempts %v", decision, err, attempts)
	}
}

func TestNativePACAuthenticationRetryIsBoundedAndErrorSpecific(t *testing.T) {
	for _, tc := range []struct {
		name         string
		failures     []error
		wantAttempts []int32
		wantErr      error
	}{
		{"unchallenged direct", []error{nil}, []int32{0}, nil},
		{"no discovery", []error{syscall.Errno(12180)}, []int32{0}, syscall.Errno(12180)},
		{"malformed script", []error{syscall.Errno(12166)}, []int32{0}, syscall.Errno(12166)},
		{"download failure", []error{syscall.Errno(12167)}, []int32{0}, syscall.Errno(12167)},
		{"rejected OS credentials", []error{syscall.Errno(12015), syscall.Errno(12015)}, []int32{0, 1}, syscall.Errno(12015)},
		{"script failure after authentication", []error{syscall.Errno(12015), syscall.Errno(12166)}, []int32{0, 1}, syscall.Errno(12166)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts []int32
			d, err := resolveAutoProxyOptions("https://target.example/", proxyConfig{AutoDetect: true}, func(_ *uint16, options *nativeAutoProxyOptions) (proxyDecision, error) {
				if len(attempts) >= len(tc.failures) {
					t.Fatal("unbounded native PAC retry")
				}
				failure := tc.failures[len(attempts)]
				attempts = append(attempts, options.AutoLogon)
				if failure != nil {
					return proxyDecision{}, failure
				}
				return proxyDecision{Direct: true}, nil
			})
			if !errors.Is(err, tc.wantErr) || !reflect.DeepEqual(attempts, tc.wantAttempts) || (err == nil && !d.Direct) {
				t.Fatalf("decision %#v error %v auth attempts %v", d, err, attempts)
			}
		})
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
