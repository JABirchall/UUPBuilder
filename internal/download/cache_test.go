//go:build windows

package download

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

func TestAllSourceDigestsAlsoProduceInternalSHA256(t *testing.T) {
	data := []byte("abc")
	md5sum := md5.Sum(data)
	sha1sum := sha1.Sum(data)
	sha256sum := sha256.Sum256(data)
	sha384sum := sha512.Sum384(data)
	sha512sum := sha512.Sum512(data)
	values := map[model.DigestAlgorithm][]byte{model.DigestMD5: md5sum[:], model.DigestSHA1: sha1sum[:], model.DigestSHA256: sha256sum[:], model.DigestSHA384: sha384sum[:], model.DigestSHA512: sha512sum[:]}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	defer srv.Close()
	m := manager(t, testOptions(t))
	for algorithm, value := range values {
		t.Run(string(algorithm), func(t *testing.T) {
			p := payload(t, data, string(algorithm)+".bin")
			p.Identity.Digest = model.Digest{Algorithm: algorithm, Value: hex.EncodeToString(value)}
			got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertFile(t, got, p, data)
		})
	}
}

func TestCorruptCacheRecordAndUnpublishedStagingAreNotHits(t *testing.T) {
	for _, kind := range []string{"record", "missing-data", "staging"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOptions(t)
			m := manager(t, opts)
			p := payload(t, fixture, "p.bin")
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write(fixture) }))
			defer srv.Close()
			if kind != "staging" {
				if _, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "record":
				f, err := opts.Cache.OpenFile(p.Identity.Key()+".json", os.O_TRUNC|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				f.WriteString("{broken")
				f.Close()
			case "missing-data":
				if err := opts.Cache.Remove(p.Identity.Key() + ".data"); err != nil {
					t.Fatal(err)
				}
			case "staging":
				f, err := opts.Cache.OpenFile(p.Identity.Key()+".staging", os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				f.Write(fixture)
				f.Close()
			}
			got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertFile(t, got, p, fixture)
			want := int32(2)
			if kind == "staging" {
				want = 1
			}
			if requests.Load() != want {
				t.Fatalf("requests=%d, want fresh download", requests.Load())
			}
		})
	}
}

func TestInterruptedPartialSurvivesManagerAndWorkspaceReopen(t *testing.T) {
	opts := testOptions(t)
	opts.Retries = 0
	m := manager(t, opts)
	p := payload(t, fixture, "p.bin")
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			initial(w, fixture, 13)
			return
		}
		if r.Header.Get("Range") != "bytes=13-" {
			t.Errorf("restart range=%q", r.Header.Get("Range"))
		}
		ranged(w, fixture, 13, `"original"`)
	}))
	defer srv.Close()
	if _, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil); err == nil {
		t.Fatal("interruption should fail without retries")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	cacheID, jobID := opts.Cache.Identity(), opts.Job.Identity()
	opts.Cache.Close()
	opts.Job.Close()
	cache, err := windows.OpenWorkspace(cacheID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.Close() })
	job, err := windows.OpenWorkspace(jobID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { job.Close() })
	opts.Cache = cache
	opts.Job = job
	m2 := manager(t, opts)
	got, err := m2.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, got, p, fixture)
	if count.Load() != 2 {
		t.Fatal(fmt.Sprintf("requests=%d", count.Load()))
	}
}

func TestManagerLeasesEachRootAndRollsBackFailedAcquisition(t *testing.T) {
	opts := testOptions(t)
	_ = manager(t, opts)
	fresh := testOptions(t)
	for _, pair := range [][2]*windows.Workspace{{opts.Job, fresh.Job}, {fresh.Cache, opts.Cache}, {fresh.Cache, opts.Job}} {
		candidate := fresh
		candidate.Cache = pair[0]
		candidate.Job = pair[1]
		if m, err := NewManager(candidate); err != ErrInUse {
			if m != nil {
				m.Close()
			}
			t.Fatalf("independent root lease=%v", err)
		}
	}
	m, err := NewManager(fresh)
	if err != nil {
		t.Fatalf("failed acquisition leaked first lease: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}
