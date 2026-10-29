package engine

import (
	"context"
	"io"
	"os"
	"slices"
	"sync"
	"uupbuilder/internal/engine/source"
)

type BootMediaReceipt struct {
	MediaDigest, BootSHA256, BootProofDigest, Digest             string
	MissingImages                                                []string
	ArchiveBytesVerified, Complete, NativeFilesystemPreservation bool
}

// BootMediaArtifact is an internal borrowed ISO namespace. Source media and a
// real transformed boot WIM meet here; install.wim and operational assembly are
// still absent. Close revokes this view, never closes either caller-owned input.
type BootMediaArtifact struct {
	mu      sync.RWMutex
	media   *MediaTreeArtifact
	boot    *SetupBootArtifact
	receipt BootMediaReceipt
	closed  bool
}

func (a *BootMediaArtifact) Receipt() BootMediaReceipt {
	if a == nil {
		return BootMediaReceipt{}
	}
	d := a.receipt
	d.MissingImages = slices.Clone(d.MissingImages)
	return d
}
func (a *BootMediaArtifact) checkLive() error {
	if a == nil || a.media == nil || a.boot == nil {
		return ErrInput
	}
	if a.closed {
		return os.ErrClosed
	}
	if _, e := a.media.EntryAt(0); e != nil {
		return e
	}
	_, e := a.boot.ReadAt(nil, 0)
	return e
}
func (a *BootMediaArtifact) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	return nil
}

// BindBootMedia binds the actual verified predecessor digests and exact source
// recipe lineage. It mutates no files and cannot replace transaction/stage or
// toolchain authority. The remaining generated-image gap stays explicit.
func BindBootMedia(ctx context.Context, media *MediaTreeArtifact, boot *SetupBootArtifact) (*BootMediaArtifact, error) {
	if ctx == nil || media == nil || boot == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	a := &BootMediaArtifact{media: media, boot: boot}
	if e := a.checkLive(); e != nil {
		return nil, e
	}
	m, b := media.Receipt(), boot.Receipt()
	if !m.SourceFilesVerified || !b.RecordsVerified || !b.Archive.BytesVerified || b.Archive.SHA256 == "" || b.Source.ProofDigest != b.Archive.ProofDigest || b.Source.RuleDigest != b.Archive.RecipeDigest || b.Source.Media.ProofDigest != m.Source.ProofDigest || b.Source.Source != m.Source.Source || b.Source.ManifestDigest != m.Source.ManifestDigest || m.Digest == "" || len(m.MissingImages) != 2 {
		return nil, ErrInput
	}
	missing := []string{}
	found := false
	for _, p := range m.MissingImages {
		key, e := source.MediaPathKey(p)
		if e != nil {
			return nil, ErrInput
		}
		switch key {
		case "sources/boot.wim":
			if found {
				return nil, ErrInput
			}
			found = true
		case "sources/install.wim":
			missing = append(missing, p)
		default:
			return nil, ErrInput
		}
	}
	if !found || len(missing) != 1 {
		return nil, ErrInput
	}
	a.receipt = BootMediaReceipt{MediaDigest: m.Digest, BootSHA256: b.Archive.SHA256, BootProofDigest: b.Source.ProofDigest, MissingImages: missing, ArchiveBytesVerified: true}
	a.receipt.Digest = mediaDigest(a.receipt)
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := a.checkLive(); e != nil {
		return nil, e
	}
	return a, nil
}

type bootMediaReader struct {
	owner  *BootMediaArtifact
	reader io.Reader
}

func (r *bootMediaReader) Read(b []byte) (int, error) {
	r.owner.mu.RLock()
	defer r.owner.mu.RUnlock()
	if e := r.owner.checkLive(); e != nil {
		return 0, e
	}
	return r.reader.Read(b)
}
func (a *BootMediaArtifact) Open(path string) (io.Reader, error) {
	if a == nil {
		return nil, ErrInput
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if e := a.checkLive(); e != nil {
		return nil, e
	}
	key, e := source.MediaPathKey(path)
	if e != nil {
		return nil, ErrInput
	}
	var r io.Reader
	if key == "sources/boot.wim" {
		r = io.NewSectionReader(a.boot, 0, int64(a.boot.Receipt().Archive.Size))
	} else {
		r, e = a.media.Open(path)
		if e != nil {
			return nil, e
		}
	}
	return &bootMediaReader{a, r}, nil
}
