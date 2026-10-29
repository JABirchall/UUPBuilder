package wimindex

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/rawlzms"
)

func decodeBounds(l DecodeLimits) (DecodeLimits, error) {
	ints := []*int{&l.MaxResources, &l.MaxChunks, &l.MaxChunkBytes, &l.MaxBufferBytes}
	for i, cap := range []int{256, 16384, 1 << 20, 2 << 20} {
		if *ints[i] < 0 || *ints[i] > cap {
			return l, ErrLimit
		}
		if *ints[i] == 0 {
			*ints[i] = cap
		}
	}
	values := []*uint64{&l.MaxResourceBytes, &l.MaxTotalBytes, &l.MaxReadBytes}
	for i, cap := range []uint64{64 << 20, 256 << 20, 256 << 20} {
		if *values[i] > cap {
			return l, ErrLimit
		}
		if *values[i] == 0 {
			*values[i] = cap
		}
	}
	return l, nil
}

type systemCodec struct{ *rawlzms.Provider }

func (p systemCodec) Identity() CodecIdentity {
	i := p.Provider.Identity()
	return CodecIdentity{Name: i.Name, SHA256: i.SHA256, Size: i.Size}
}
func systemMetadataCodec(ctx context.Context) (metadataCodec, error) {
	path, err := rawlzms.SystemPath()
	if err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	p, err := rawlzms.Open(ctx, path)
	if err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	return systemCodec{p}, nil
}

type metadataWork struct {
	view      *sourceView
	container Container
	entry     Entry
	table     standardTable
}

func decodeMetadata(ctx context.Context, manifest model.PayloadManifest, files []metadata.LocalResource, idx *Index, limits DecodeLimits, factory codecFactory) (result []*MetadataArtifact, runErr error) {
	if ctx == nil || idx == nil {
		return nil, ErrInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l, err := decodeBounds(limits)
	if err != nil {
		return nil, err
	}
	manifest = model.PayloadManifest{Source: manifest.Source, Payloads: slices.Clone(manifest.Payloads), Queries: model.CloneSourceQueries(manifest.Queries), Digest: manifest.Digest}
	files = slices.Clone(files)
	if manifest.Validate() != nil || idx.state.Source != manifest.Source || idx.state.ManifestDigest != manifest.Digest || len(files) == 0 || len(files) != len(idx.state.Containers) {
		return nil, ErrInput
	}
	serialized, err := idx.MarshalJSON()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(serialized)
	if idx.digest != hex.EncodeToString(digest[:]) {
		return nil, ErrIntegrity
	}
	refs := map[model.PayloadIdentity]metadata.LocalResource{}
	for _, f := range files {
		found := false
		for _, p := range manifest.Payloads {
			if p.Identity == f.Identity {
				found = true
				break
			}
		}
		if !found || f.Identity.Validate() != nil || f.Identity.Encryption.Method != "" {
			return nil, ErrInput
		}
		if _, ok := refs[f.Identity]; ok {
			return nil, ErrInput
		}
		refs[f.Identity] = f
	}
	var views []*sourceView
	var pending []*MetadataArtifact
	var codec metadataCodec
	defer func() {
		if codec != nil {
			runErr = errors.Join(runErr, codec.Close())
		}
		for _, v := range views {
			runErr = errors.Join(runErr, v.file.Close())
		}
		if runErr != nil {
			for _, a := range pending {
				runErr = errors.Join(runErr, a.Close())
			}
			result = nil
		}
	}()
	var work []metadataWork
	var total, reads uint64
	// Verify every retained handle and independently compare parsed descriptors
	// with the frozen reviewed index before consuming any metadata resource.
	for _, c := range idx.state.Containers {
		f, ok := refs[c.Payload]
		if !ok {
			return nil, ErrInput
		}
		delete(refs, c.Payload)
		v, err := openSource(ctx, f)
		if err != nil {
			return nil, err
		}
		views = append(views, v)
		sha, err := v.rehash()
		if err != nil {
			return nil, err
		}
		if sha != c.SourceSHA256 || !c.SourceRehashed {
			return nil, ErrIntegrity
		}
		actual, _, err := readContainer(ctx, v, uint64(f.Identity.Size), f.Identity, Limits{64, 262144, 524288, 1 << 20}, 524288)
		if err != nil {
			return nil, err
		}
		actual.SourceSHA256 = sha
		actual.SourceRehashed = true
		if !reflect.DeepEqual(actual, c) {
			return nil, ErrIntegrity
		}
		for _, e := range c.Entries {
			if e.Kind != "metadata" {
				continue
			}
			if !e.Located || e.References != 1 || e.ImageIndex == 0 || !c.MappingComplete || e.SHA1 == zeroSHA1 || e.LogicalSize == 0 {
				return nil, ErrUnsupported
			}
			if e.Descriptor.Flags != 2 && e.Descriptor.Flags != 6 {
				return nil, ErrUnsupported
			}
			if e.Location.LogicalOffset != 0 || e.Location.ResourceEntry != e.Ordinal || e.Location.PhysicalOffset != e.Descriptor.Offset || e.Location.PhysicalSize != e.Descriptor.Size || e.Location.ResourceLogicalSize != e.LogicalSize || e.Descriptor.Original != e.LogicalSize {
				return nil, ErrIntegrity
			}
			if len(work) >= l.MaxResources || e.LogicalSize > l.MaxResourceBytes || e.LogicalSize > l.MaxTotalBytes-total {
				return nil, ErrLimit
			}
			total += e.LogicalSize
			w := metadataWork{view: v, container: c, entry: e}
			read := e.Descriptor.Size
			if e.Descriptor.Flags == 6 {
				if e.Location.Compression != 3 {
					return nil, ErrUnsupported
				}
				p, err := standardShape(e.LogicalSize, e.Descriptor.Size, uint64(e.Location.ChunkSize))
				if err != nil {
					return nil, err
				}
				if p.count > uint64(l.MaxChunks) || uint64(e.Location.ChunkSize) > uint64(l.MaxChunkBytes) {
					return nil, ErrLimit
				}
				if read > l.MaxReadBytes || p.bytes > l.MaxReadBytes-read {
					return nil, ErrLimit
				}
				read += p.bytes
				w.table = p
			} else if e.Location.Compression != 0 || e.Location.ChunkSize != 0 || read != e.LogicalSize {
				return nil, ErrIntegrity
			}
			if read > l.MaxReadBytes-reads {
				return nil, ErrLimit
			}
			reads += read
			work = append(work, w)
		}
	}
	if len(refs) != 0 || len(work) == 0 {
		return nil, ErrInput
	}
	// Validate all table entries before loading the codec or allocating buffers.
	for _, w := range work {
		if w.entry.Descriptor.Flags == 6 {
			if _, err := validateStandard(ctx, w.view, uint64(w.container.Payload.Size), w.entry, l); err != nil {
				return nil, err
			}
		}
	}
	for _, w := range work {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if w.entry.Descriptor.Flags == 6 && codec == nil {
			codec, err = factory(ctx)
			if err != nil {
				return nil, err
			}
		}
		a, err := decodeMetadataResource(ctx, w, l, codec)
		if err != nil {
			return nil, err
		}
		pending = append(pending, a)
	}
	for i, v := range views {
		sha, err := v.rehash()
		if err != nil {
			return nil, err
		}
		if sha != idx.state.Containers[i].SourceSHA256 {
			return nil, ErrIntegrity
		}
	}
	if codec != nil {
		err := codec.Close()
		codec = nil
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, a := range pending {
		a.receipt.Source = manifest.Source
		a.receipt.ManifestDigest = manifest.Digest
		a.receipt.IndexDigest = idx.digest
		a.receipt.SourceRehashed = true
	}
	return pending, nil
}
func decodeMetadataResource(ctx context.Context, w metadataWork, l DecodeLimits, codec metadataCodec) (a *MetadataArtifact, runErr error) {
	f, err := os.CreateTemp("", "uup-metadata-unverified-*")
	if err != nil {
		return nil, err
	}
	a = &MetadataArtifact{file: f, path: f.Name()}
	success := false
	defer func() {
		if !success {
			runErr = errors.Join(runErr, a.Close())
			a = nil
		}
	}()
	h1, h256 := sha1.New(), sha256.New()
	out := io.MultiWriter(f, h1, h256)
	if w.entry.Descriptor.Flags == 6 {
		err = streamStandard(ctx, w.view, uint64(w.container.Payload.Size), w.entry, l, w.table, codec, out)
	} else {
		buf := make([]byte, min(64<<10, l.MaxBufferBytes, l.MaxChunkBytes))
		var n int64
		n, err = io.CopyBuffer(out, io.NewSectionReader(w.view, int64(w.entry.Descriptor.Offset), int64(w.entry.LogicalSize)), buf)
		if err == nil && uint64(n) != w.entry.LogicalSize {
			err = ErrIntegrity
		}
	}
	if err != nil {
		return a, err
	}
	if err := ctx.Err(); err != nil {
		return a, err
	}
	info, err := f.Stat()
	if err != nil {
		return a, err
	}
	sha := hex.EncodeToString(h1.Sum(nil))
	if uint64(info.Size()) != w.entry.LogicalSize || sha != w.entry.SHA1 {
		return a, ErrIntegrity
	}
	decodedSHA256, err := verifyDecoded(ctx, f, w.entry.LogicalSize, w.entry.SHA1)
	if err != nil {
		return a, err
	}
	if decodedSHA256 != hex.EncodeToString(h256.Sum(nil)) {
		return a, ErrIntegrity
	}
	a.receipt = MetadataReceipt{Payload: w.container.Payload, SourceSHA256: w.container.SourceSHA256, Header: w.container.Header, Entry: w.entry, SHA1: sha, SHA256: decodedSHA256, Size: uint64(info.Size())}
	if codec != nil && w.entry.Descriptor.Flags == 6 {
		a.receipt.Codec = codec.Identity()
	}
	success = true
	return a, nil
}

func verifyDecoded(ctx context.Context, f *os.File, size uint64, sha1 string) (string, error) {
	info, err := f.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) != size {
		return "", ErrIntegrity
	}
	v := sourceView{ctx: ctx, file: f, path: f.Name(), initial: info, identity: model.PayloadIdentity{Size: info.Size(), Digest: model.Digest{Algorithm: model.DigestSHA1, Value: sha1}}}
	return v.rehash()
}
