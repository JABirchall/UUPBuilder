package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"sync"
	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/metadata/privatestore"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

type MediaTreeLimits struct {
	MaxEntries, MaxResources, MaxBufferBytes     int
	MaxOutputBytes, MaxReadBytes, MaxResultBytes uint64
}
type MediaTreeReceipt struct {
	Source                                                      source.MediaTreeDescriptor
	Files, Directories, Resources                               int
	MissingImages                                               []string
	Digest                                                      string
	Bytes, ReadBytes, AccountedBytes                            uint64
	SourceFilesVerified, Complete, NativeFilesystemPreservation bool
}

// MediaTreeArtifact owns flat byte objects and logical ISO paths. It is an
// internal source-file component. It cannot supply generated image grafts,
// grant native preservation, or represent a completed assembly/ReadyPlan.
type MediaTreeArtifact struct {
	mu       sync.RWMutex
	store    *privatestore.Store
	files    []*privatestore.File
	entries  []source.MediaEntry
	lookup   map[string]int
	receipt  MediaTreeReceipt
	closed   bool
	closeErr error
}

func mediaBounds(l MediaTreeLimits) (MediaTreeLimits, error) {
	for i, p := range []*int{&l.MaxEntries, &l.MaxResources, &l.MaxBufferBytes} {
		cap := []int{262144, 262144, 64 << 10}[i]
		if *p < 0 || *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for i, p := range []*uint64{&l.MaxOutputBytes, &l.MaxReadBytes, &l.MaxResultBytes} {
		cap := []uint64{8 << 30, 64 << 30, 512 << 20}[i]
		if *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}
func mediaDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// MaterializeMediaTree copies each unique source stream and original metadata
// once. It verifies complete source/output bytes and source custody before
// publishing. Empty files and duplicate-content names remain distinct entries.
func MaterializeMediaTree(ctx context.Context, r *source.BoundMediaTree, limits MediaTreeLimits) (result *MediaTreeArtifact, runErr error) {
	if ctx == nil || r == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := mediaBounds(limits)
	if e != nil {
		return nil, e
	}
	if e = r.CheckLive(); e != nil {
		return nil, e
	}
	d := r.Descriptor()
	accounted := d.AccountedBytes + uint64(d.Entries)*2048 + uint64(d.Resources)*4096 + 4096
	if d.Resources < 1 || d.Entries < 1 || d.Entries > l.MaxEntries || d.Resources > l.MaxResources || d.ResourceBytes > l.MaxOutputBytes || d.ResourceBytes > l.MaxReadBytes/3 || accounted > l.MaxResultBytes || l.MaxBufferBytes < 64<<10 {
		return nil, ErrLimit
	}
	entries := make([]source.MediaEntry, d.Entries)
	lookup := make(map[string]int, d.Entries)
	for i := range entries {
		en, e := r.EntryAt(i)
		if e != nil {
			return nil, e
		}
		key, e := source.MediaPathKey(en.Path)
		if e != nil {
			return nil, ErrInput
		}
		entries[i] = en
		lookup[key] = i
	}
	volume, e := platform.InspectStorage(os.TempDir())
	if e != nil {
		return nil, e
	}
	if d.ResourceBytes > volume.AvailableBytes || 64<<20 > volume.AvailableBytes-d.ResourceBytes {
		return nil, ErrLimit
	}
	ids := make([]source.ResourceIdentity, d.Resources)
	for i := range ids {
		id, _, e := r.Resource(i)
		if e != nil {
			return nil, e
		}
		if id.Size > volume.MaxFileBytes {
			return nil, ErrLimit
		}
		ids[i] = id
	}
	store, e := privatestore.New(privatestore.Profile{MaxFiles: d.Resources, MaxBytes: d.ResourceBytes}, "source-media-files")
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			runErr = errors.Join(runErr, store.Close())
			result = nil
		}
	}()
	files := make([]*privatestore.File, d.Resources)
	budget := &readBudget{limit: l.MaxReadBytes}
	for i, id := range ids {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		_, reader, e := r.Resource(i)
		if e != nil {
			return nil, e
		}
		f, name, e := store.Create(id.Size)
		if e != nil {
			return nil, e
		}
		h1, h256, copyErr := hashCopy(ctx, f, countedReader{ctx, reader, budget}, id.Size)
		if copyErr == nil && (h1 != id.SHA1 || h256 != id.SHA256) {
			copyErr = ErrIntegrity
		}
		if copyErr == nil {
			copyErr = f.Sync()
		}
		if e = errors.Join(copyErr, f.Close()); e != nil {
			return nil, e
		}
		retained, e := store.Retain(name, id.Size)
		if e != nil {
			return nil, e
		}
		files[i] = retained
		if e = budget.charge(id.Size); e != nil {
			return nil, e
		}
		if e = retained.Verify(ctx, model.DigestSHA256, id.SHA256, id.SHA256); e != nil {
			return nil, e
		}
	}
	// Original live producers are checked again after all copies.
	for i, id := range ids {
		_, reader, e := r.Resource(i)
		if e != nil {
			return nil, e
		}
		h1, h256, e := hashCopy(ctx, nil, countedReader{ctx, reader, budget}, id.Size)
		if e != nil || h1 != id.SHA1 || h256 != id.SHA256 {
			return nil, errors.Join(ErrIntegrity, e)
		}
	}
	if e = store.Verify(ctx); e != nil {
		return nil, e
	}
	if e = r.CheckLive(); e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	receipt := MediaTreeReceipt{Source: d, Files: d.Files, Directories: d.Directories, Resources: d.Resources, MissingImages: slices.Clone(d.ReservedPaths), Bytes: d.ResourceBytes, ReadBytes: budget.used, AccountedBytes: accounted, SourceFilesVerified: true}
	receipt.Digest = mediaDigest(struct {
		Receipt   MediaTreeReceipt
		Entries   []source.MediaEntry
		Resources []source.ResourceIdentity
	}{receipt, entries, ids})
	result = &MediaTreeArtifact{store: store, files: files, entries: entries, lookup: lookup, receipt: receipt}
	success = true
	return result, nil
}
func (a *MediaTreeArtifact) Receipt() MediaTreeReceipt {
	if a == nil {
		return MediaTreeReceipt{}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	d := a.receipt
	d.MissingImages = slices.Clone(d.MissingImages)
	d.Source.ReservedPaths = slices.Clone(d.Source.ReservedPaths)
	return d
}
func (a *MediaTreeArtifact) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.closed = true
		if a.store != nil {
			a.closeErr = a.store.Close()
		}
	}
	return a.closeErr
}
func (a *MediaTreeArtifact) EntryAt(n int) (source.MediaEntry, error) {
	if a == nil {
		return source.MediaEntry{}, ErrInput
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return source.MediaEntry{}, os.ErrClosed
	}
	if n < 0 || n >= len(a.entries) {
		return source.MediaEntry{}, ErrInput
	}
	return a.entries[n], nil
}

type mediaReader struct {
	owner        *MediaTreeArtifact
	resource     int
	size, offset uint64
}

func (r *mediaReader) Read(b []byte) (int, error) {
	a := r.owner
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return 0, os.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	if r.offset >= r.size {
		return 0, io.EOF
	}
	if r.resource < 0 {
		return 0, ErrIntegrity
	}
	if uint64(len(b)) > r.size-r.offset {
		b = b[:r.size-r.offset]
	}
	n, e := a.files[r.resource].ReadAt(b, int64(r.offset))
	r.offset += uint64(n)
	return n, e
}
func (a *MediaTreeArtifact) Open(path string) (io.Reader, error) {
	if a == nil {
		return nil, ErrInput
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return nil, os.ErrClosed
	}
	key, e := source.MediaPathKey(path)
	if e != nil {
		return nil, ErrInput
	}
	n, ok := a.lookup[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	en := a.entries[n]
	if en.Directory {
		return nil, ErrInput
	}
	return &mediaReader{owner: a, resource: en.Resource, size: en.Size}, nil
}
func (a *MediaTreeArtifact) OriginalMetadata() (io.Reader, error) {
	if a == nil {
		return nil, ErrInput
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return nil, os.ErrClosed
	}
	if len(a.files) == 0 {
		return nil, ErrInput
	}
	return &mediaReader{owner: a, resource: 0, size: a.receipt.Source.Metadata.Size}, nil
}
