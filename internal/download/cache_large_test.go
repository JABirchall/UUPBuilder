//go:build windows && download_large

package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

// Explicit R1 opt-in: writes real, dense >4GiB job/cache files, requiring over
// 8GiB of free local NTFS space and several complete hashing passes. It never
// skips missing prerequisites and refuses to present WOW64/emulation as native
// host evidence. Ordinary tests and compile-only checks do not run this probe.
func TestActualLargeTransferResumeAndCacheRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	host, err := windows.DetectHost(ctx)
	if err != nil {
		t.Fatal("native host evidence unavailable:", err)
	}
	if host.ProcessArchitecture != host.NativeArchitecture {
		t.Fatalf("unverified native host: process=%s native=%s", host.ProcessArchitecture, host.NativeArchitecture)
	}
	if host.NativeArchitecture != model.ArchitectureX86 && host.NativeArchitecture != model.ArchitectureAMD64 && host.NativeArchitecture != model.ArchitectureARM64 {
		t.Fatal("unsupported native evidence host")
	}
	const size int64 = 1<<32 + 2<<20 + 17
	const cut int64 = 1<<32 + 17
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = byte(i%251 + 1)
	}
	h := sha256.New()
	if err := writeDenseFixture(ctx, h, block, 0, size); err != nil {
		t.Fatal(err)
	}
	expected := hex.EncodeToString(h.Sum(nil))
	p, err := model.NewPayload(model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: expected}, Size: size, Provenance: model.PackageProvenance{Source: "local-large-fixture", Name: "large.bin"}}, "large.bin")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"large-fixture-v1"`)
		if requests.Add(1) == 1 {
			if r.Header.Get("Range") != "" {
				t.Error("initial request had Range")
			}
			w.Header().Set("Content-Length", fmt.Sprint(size))
			if err := writeDenseFixture(r.Context(), w, block, 0, cut); err != nil {
				t.Error(err)
			}
			return
		}
		if r.Header.Get("Range") != fmt.Sprintf("bytes=%d-", cut) {
			t.Errorf("actual resume offset was not %d", cut)
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", cut, size-1, size))
		w.Header().Set("Content-Length", fmt.Sprint(size-cut))
		w.WriteHeader(206)
		if err := writeDenseFixture(r.Context(), w, block, cut, size-cut); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	opts := testOptions(t)
	opts.Retries = 0
	opts.RequestTimeout = 20 * time.Minute
	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { m.Close(); opts.Job.Close(); opts.Cache.Close() }()
	if _, err = m.FetchOne(ctx, p, Locator{URL: srv.URL}, nil); !errors.Is(err, ErrTransfer) {
		t.Fatalf("actual interruption=%v", err)
	}
	f, err := opts.Job.OpenFile(p.Identity.Key()+".part", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	f.Close()
	if err != nil || st.Size() != cut {
		t.Fatalf("actual >4GiB partial size: %v %v", st, err)
	}
	reopen := func() {
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		cacheID, jobID := opts.Cache.Identity(), opts.Job.Identity()
		opts.Cache.Close()
		opts.Job.Close()
		var err error
		opts.Cache, err = windows.OpenWorkspace(cacheID)
		if err != nil {
			t.Fatal(err)
		}
		opts.Job, err = windows.OpenWorkspace(jobID)
		if err != nil {
			t.Fatal(err)
		}
		m, err = NewManager(opts)
		if err != nil {
			t.Fatal(err)
		}
	}
	reopen()
	got, err := m.FetchOne(ctx, p, Locator{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err = opts.Cache.OpenFile(p.Identity.Key()+".data", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	h = sha256.New()
	n, err := io.Copy(h, f)
	f.Close()
	if err != nil || n != size || hex.EncodeToString(h.Sum(nil)) != expected || got.SHA256 != expected {
		t.Fatalf("actual final size/hash verification failed: bytes=%d err=%v", n, err)
	}
	reopen()
	got, err = m.FetchOne(ctx, p, Locator{}, nil)
	if err != nil || got.SHA256 != expected || requests.Load() != 2 {
		t.Fatalf("actual cache restart failed: requests=%d err=%v", requests.Load(), err)
	}
	t.Logf("actual native=%s WindowsBuild=%d; interruption=%d final=%d SHA256=%s; resumed and reused after workspace reopen", host.NativeArchitecture, host.WindowsBuild, cut, size, expected)
}

func writeDenseFixture(ctx context.Context, w io.Writer, block []byte, offset, length int64) error {
	for length > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := offset % int64(len(block))
		count := min(length, int64(len(block))-start)
		n, err := w.Write(block[int(start):int(start+count)])
		if err != nil {
			return err
		}
		if int64(n) != count {
			return io.ErrShortWrite
		}
		offset += int64(n)
		length -= int64(n)
	}
	return nil
}
