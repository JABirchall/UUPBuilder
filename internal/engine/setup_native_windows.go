package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/model"
)

// InspectSetupReadOnly observes format and identity interoperability only. It
// borrows the exact live Setup producer and retains the archive read lock until
// native cleanup and both source/output postchecks finish. Individual native
// calls and allocations cannot be preempted; the fixed body checks between calls.
func InspectSetupReadOnly(ctx context.Context, a *SetupBootArtifact) (out NativeObservation, runErr error) {
	l, e := beginSetupReadOnly(ctx, a)
	if e != nil {
		return out, e
	}
	defer l.finish(ctx, &out, &runErr)
	return inspectReadOnlyLocked(ctx, a.archive, &l.summary)
}

// This private lease selects no provider, path, flags or native operation. The
// lock order is archive -> retained file; Close takes the archive write lock.
type setupReadOnlyLease struct {
	artifact *SetupBootArtifact
	summary  source.ImageSummary
}

func beginSetupReadOnly(ctx context.Context, a *SetupBootArtifact) (*setupReadOnlyLease, error) {
	if ctx == nil || a == nil || a.archive == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	a.archive.mu.RLock()
	if e := a.checkSetupReadOnly(ctx); e != nil {
		a.archive.mu.RUnlock()
		return nil, e
	}
	return &setupReadOnlyLease{a, a.source.OutputSummary}, nil
}

func (l *setupReadOnlyLease) finish(ctx context.Context, out *NativeObservation, runErr *error) {
	defer l.artifact.archive.mu.RUnlock()
	*runErr = errors.Join(*runErr, l.artifact.checkSetupReadOnly(ctx))
	if *runErr != nil {
		out.FormatInteroperable = false
	}
}

// Caller holds archive.mu for the whole inspection, including final native
// cleanup. Parent producers retain their existing revocation checks.
func (a *SetupBootArtifact) checkSetupReadOnly(ctx context.Context) error {
	b := a.archive
	if b.closed {
		return os.ErrClosed
	}
	if a.recipe == nil || b.file == nil || b.store == nil {
		return ErrInput
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := a.recipe.CheckLive(); e != nil {
		return e
	}
	if e := b.store.Verify(ctx); e != nil {
		return e
	}
	d := a.recipe.Descriptor()
	s := b.receipt
	if !reflect.DeepEqual(d, a.source) || d.Source.Architecture != "x86" || d.Source.Language != "en-us" || d.Source != d.Index.Source || d.ManifestDigest != d.Index.ManifestDigest || d.Source != d.Media.Source || d.ManifestDigest != d.Media.ManifestDigest || d.RuleDigest == "" || d.ProofDigest == "" || s.RecipeDigest != d.RuleDigest || s.ProofDigest != d.ProofDigest || !s.BytesVerified || s.WindowsCompatible || s.NativeFilesystemPreservation || b.expected != (ImageInformation{1, "0", "WindowsPE", "WindowsPE", "10.0.19041.1"}) || len(s.Resources) != d.Resources || d.Resources < 1 || s.Size > 8<<30 || s.Size < s.XMLOffset || s.Size-s.XMLOffset != d.XMLBytes || d.XMLBytes > 1<<20 {
		return ErrInput
	}
	// Bind every retained output resource to the exact live producer, including
	// the boot metadata at offset 208 and its logical/physical descriptor sizes.
	offset := uint64(208)
	for i, v := range s.Resources {
		id, _, e := a.recipe.Resource(i)
		if e != nil {
			return e
		}
		if v.SHA1 != id.SHA1 || v.SHA256 != id.SHA256 || v.Size != id.Size || v.References != id.References || v.Offset != offset || v.Metadata != (i == 0) {
			return ErrIntegrity
		}
		offset += v.Size
	}
	if offset != s.LookupOffset || offset+uint64(d.Resources)*50 != s.XMLOffset {
		return ErrIntegrity
	}
	var h [208]byte
	if n, e := b.file.ReadAt(h[:], 0); e != nil || n != len(h) {
		return errors.Join(ErrIntegrity, e)
	}
	le := binary.LittleEndian
	if le.Uint32(h[44:]) != 1 || le.Uint32(h[120:]) != 1 || h[103] != 2 || le.Uint64(h[96:])&0x00ffffffffffffff != d.MetadataBytes || le.Uint64(h[104:]) != 208 || le.Uint64(h[112:]) != d.MetadataBytes || s.Resources[0].Size != d.MetadataBytes || s.Resources[0].SHA256 != d.MetadataSHA256 {
		return ErrIntegrity
	}
	return b.file.Verify(ctx, model.DigestSHA256, s.SHA256, s.SHA256)
}
