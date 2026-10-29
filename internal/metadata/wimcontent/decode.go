package wimcontent

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/metadata/privatestore"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/rawlzms"
)

type codec interface {
	DecodeInto(context.Context, []byte, []byte) error
	Identity() rawlzms.Identity
	Close() error
}
type codecFactory func(context.Context, Limits) (codec, error)

func systemCodec(ctx context.Context, l Limits) (codec, error) {
	return rawlzms.OpenSolid(ctx, rawlzms.SolidLimits{MaxInputBytes: l.MaxChunkBytes, MaxOutputBytes: l.MaxChunkBytes})
}

type readBudget struct{ limit, used uint64 }

func (b *readBudget) charge(n uint64) error {
	if n > b.limit-b.used {
		return ErrLimit
	}
	b.used += n
	return nil
}

type countedReader struct {
	ctx    context.Context
	r      io.ReaderAt
	budget *readBudget
}

func (r countedReader) ReadAt(b []byte, off int64) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if e := r.budget.charge(uint64(len(b))); e != nil {
		return 0, e
	}
	n, e := r.r.ReadAt(b, off)
	if r.ctx.Err() != nil {
		return n, r.ctx.Err()
	}
	return n, e
}

type sourceWork struct {
	local   metadata.LocalResource
	file    *os.File
	initial os.FileInfo
	receipt SourceReceipt
}
type resourceWork struct {
	container int
	entry     wimindex.Entry
	table     table
}
type resourceKey struct {
	container  int
	descriptor wimindex.Descriptor
}

func boundedManifest(m model.PayloadManifest, l Limits) (uint64, error) {
	var total uint64
	add := func(v ...string) bool {
		for _, s := range v {
			if len(s) > l.MaxVariableBytes || uint64(len(s)) > l.MaxManifestBytes-total {
				return false
			}
			total += uint64(len(s))
		}
		return true
	}
	payload := func(p model.Payload) bool {
		i := p.Identity
		if strings.Count(p.Destination, "/")+strings.Count(p.Destination, `\`) > 63 {
			return false
		}
		return add(p.Destination, string(i.Digest.Algorithm), i.Digest.Value, i.Provenance.Source, i.Provenance.Name, i.Encryption.Method, i.Encryption.Fingerprint)
	}
	if !add(m.Source.UpdateID, m.Source.BuildLabel, string(m.Source.Architecture), m.Source.Language, m.Digest) {
		return 0, ErrLimit
	}
	for _, p := range m.Payloads {
		if !payload(p) {
			return 0, ErrLimit
		}
	}
	for _, q := range m.Queries {
		if !add(q.UpdateID, q.Language, q.Edition) {
			return 0, ErrLimit
		}
		for _, p := range q.Projection {
			if !payload(p) {
				return 0, ErrLimit
			}
		}
	}
	return total, nil
}
func decode(ctx context.Context, m model.PayloadManifest, files []metadata.LocalResource, idx *wimindex.Index, limits Limits, factory codecFactory) (result *Result, runErr error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := bounds(limits)
	if e != nil {
		return nil, e
	}
	if l.MaxChunkBytes < 64<<10 || l.MaxBufferBytes < 64<<10 {
		return nil, ErrLimit
	}
	claim := idx.ContentClaim()
	if !claim.Verified || !claim.Complete || claim.Source != m.Source || claim.ManifestDigest != m.Digest || len(files) != claim.Containers || len(files) == 0 {
		return nil, ErrInput
	}
	if claim.Containers > l.MaxSources || claim.Entries > l.MaxEntries || len(m.Payloads) > l.MaxManifestPayloads || len(m.Queries) > l.MaxQueries {
		return nil, ErrLimit
	}
	projected := 0
	for _, q := range m.Queries {
		if len(q.Projection) > l.MaxProjectionPayloads-projected {
			return nil, ErrLimit
		}
		projected += len(q.Projection)
	}
	variable, e := boundedManifest(m, l)
	if e != nil {
		return nil, e
	}
	var reparseCharge, identityCharge uint64
	for n := 0; n < claim.Containers; n++ {
		c, _ := idx.ContentContainerAt(n)
		// XML decoding/tokenization and image values are bounded B1 work too;
		// do not hide their temporary allocations behind the entry-only cap.
		reparseCharge = max(reparseCharge, uint64(c.Entries)*1024+c.Header.XML.Size*16+uint64(c.Header.ImageCount)*4096)
		identityCharge += uint64(c.Entries) * identityBytes(c.Payload) * 8
	}
	// Includes conservative reparse/record/map/slice/JSON charges before any
	// manifest normalization or full-container reparse allocation.
	accounted := variable*8 + uint64(claim.Entries)*2048 + reparseCharge + identityCharge + uint64(len(m.Payloads)+projected)*16384 + uint64(len(files))*4096 + 4096
	if accounted > l.MaxResultBytes {
		return nil, ErrLimit
	}
	supplied := map[model.PayloadIdentity]metadata.LocalResource{}
	for _, f := range files {
		for _, v := range [...]string{string(f.Identity.Digest.Algorithm), f.Identity.Digest.Value, f.Identity.Provenance.Source, f.Identity.Provenance.Name, f.Identity.Encryption.Method, f.Identity.Encryption.Fingerprint} {
			if len(v) > l.MaxVariableBytes {
				return nil, ErrLimit
			}
		}
		if len(f.Path) > l.MaxPathBytes {
			return nil, ErrLimit
		}
		bound := false
		for _, p := range m.Payloads {
			if p.Identity == f.Identity {
				bound = true
				break
			}
		}
		if !bound || f.Identity.Encryption.Method != "" {
			return nil, ErrInput
		}
		if _, ok := supplied[f.Identity]; ok {
			return nil, ErrInput
		}
		supplied[f.Identity] = f
	}
	if m.Validate() != nil {
		return nil, ErrInput
	}
	m = model.PayloadManifest{Source: m.Source, Payloads: slices.Clone(m.Payloads), Queries: model.CloneSourceQueries(m.Queries), Digest: m.Digest}
	files = slices.Clone(files)
	s := Snapshot{Schema: 1, Index: claim, AccountedBytes: accounted}
	var work []resourceWork
	byKey := map[resourceKey]int{}
	var totalSource, readEstimate, blobBytes uint64
	declaredChunks := uint64(0)
	addRead := func(n uint64) bool {
		if n > l.MaxReadBytes-readEstimate {
			return false
		}
		readEstimate += n
		return true
	}
	// Derive resources exclusively from original immutable entries, canonicalizing
	// solid backing aliases by full descriptor, never by a caller range/ordinal.
	for ci := 0; ci < claim.Containers; ci++ {
		c, _ := idx.ContentContainerAt(ci)
		f, ok := supplied[c.Payload]
		if !ok || !c.SourceRehashed || !c.MappingComplete {
			return nil, ErrInput
		}
		delete(supplied, c.Payload)
		if f.Identity.Size < 0 || uint64(f.Identity.Size) > l.MaxSourceBytes || uint64(f.Identity.Size) > l.MaxTotalSourceBytes-totalSource {
			return nil, ErrLimit
		}
		totalSource += uint64(f.Identity.Size)
		if !addRead(2*uint64(f.Identity.Size)) || !addRead(uint64(c.Entries)*66+(1<<20)+208) {
			return nil, ErrLimit
		}
		s.Sources = append(s.Sources, SourceReceipt{Payload: c.Payload, SHA256: c.SourceSHA256, Header: c.Header})
		for ei := 0; ei < c.Entries; ei++ {
			en, _ := idx.ContentEntryAt(ci, ei)
			if er := ctx.Err(); er != nil {
				return nil, er
			}
			if en.Kind == "metadata" {
				continue
			}
			if !en.Located || en.LogicalSize == 0 {
				return nil, ErrUnsupported
			}
			if en.Kind != "ordinary" && en.Kind != "solid-resource" && en.Kind != "solid-blob" {
				return nil, ErrUnsupported
			}
			backing := en
			if en.Kind == "solid-blob" {
				if en.Location.ResourceEntry == 0 {
					return nil, ErrIntegrity
				}
				var yes bool
				backing, yes = idx.ContentEntryAt(ci, int(en.Location.ResourceEntry)-1)
				if !yes || backing.Kind != "solid-resource" {
					return nil, ErrIntegrity
				}
				loc := en.Location
				loc.LogicalOffset = 0
				if loc != backing.Location || en.Location.LogicalOffset > backing.LogicalSize || en.LogicalSize > backing.LogicalSize-en.Location.LogicalOffset {
					return nil, ErrIntegrity
				}
			}
			if backing.Location.PhysicalOffset != backing.Descriptor.Offset || backing.Location.PhysicalSize != backing.Descriptor.Size || backing.Location.ResourceLogicalSize != backing.LogicalSize {
				return nil, ErrIntegrity
			}
			key := resourceKey{ci, backing.Descriptor}
			bi, exists := byKey[key]
			if !exists {
				if len(work) >= l.MaxResources || backing.LogicalSize > l.MaxResourceBytes || backing.LogicalSize > l.MaxOutputBytes-s.DecodedBytes {
					return nil, ErrLimit
				}
				if backing.Kind == "ordinary" && (backing.Descriptor.Flags != 0 || backing.Location.Compression != 0) {
					return nil, ErrUnsupported
				}
				if backing.Kind == "solid-resource" {
					cs := uint64(backing.Location.ChunkSize)
					if cs == 0 || cs > uint64(l.MaxChunkBytes) {
						return nil, ErrLimit
					}
					count := 1 + (backing.LogicalSize-1)/cs
					if count > uint64(l.MaxChunks) || count > uint64(l.MaxTotalChunks)-declaredChunks || count*64 > l.MaxResultBytes-s.AccountedBytes {
						return nil, ErrLimit
					}
					declaredChunks += count
					s.AccountedBytes += count * 64
				} else {
					if declaredChunks == uint64(l.MaxTotalChunks) {
						return nil, ErrLimit
					}
					declaredChunks++
				}
				bi = len(work)
				byKey[key] = bi
				work = append(work, resourceWork{container: ci, entry: backing})
				s.DecodedBytes += backing.LogicalSize
				if !addRead(backing.Descriptor.Size) || !addRead(2*backing.LogicalSize) {
					return nil, ErrLimit
				}
			}
			if en.Kind == "solid-resource" {
				continue
			}
			if len(en.SHA1) != 40 || en.SHA1 == strings.Repeat("0", 40) {
				return nil, ErrUnsupported
			}
			if en.LogicalSize > l.MaxReadBytes-blobBytes {
				return nil, ErrLimit
			}
			blobBytes += en.LogicalSize
			if en.References == 0 {
				s.InactiveNonMetadata++
			} else {
				s.ActiveNonMetadata++
			}
			s.Witnesses = append(s.Witnesses, Witness{Payload: c.Payload, SourceSHA256: c.SourceSHA256, Header: c.Header, Entry: en, SHA1: en.SHA1, Size: en.LogicalSize, Backing: bi})
		}
	}
	if len(supplied) != 0 || len(s.Witnesses) != claim.NonMetadata || len(work) == 0 {
		return nil, ErrInput
	}
	if !addRead(2 * blobBytes) {
		return nil, ErrLimit
	}
	budget := &readBudget{limit: l.MaxReadBytes}
	var sources []sourceWork
	var provider codec
	var store *privatestore.Store
	var retained []*privatestore.File
	finalSources := false
	defer func() {
		if provider != nil {
			runErr = errors.Join(runErr, provider.Close())
		}
		for _, w := range sources {
			if !finalSources && ctx.Err() == nil {
				sha, er := verifySource(ctx, w, budget)
				if er != nil || sha != w.receipt.SHA256 {
					runErr = errors.Join(runErr, ErrIntegrity, er)
				}
			}
			runErr = errors.Join(runErr, w.file.Close())
		}
		if runErr != nil {
			if store != nil {
				runErr = errors.Join(runErr, store.Close())
			}
			result = nil
		}
	}()
	for ci, row := range s.Sources {
		var f metadata.LocalResource
		for _, candidate := range files {
			if candidate.Identity == row.Payload {
				f = candidate
				break
			}
		}
		file, initial, er := localsource.Open(f.Path, f.Identity)
		if er != nil {
			return nil, er
		}
		w := sourceWork{f, file, initial, row}
		sources = append(sources, w)
		sha, er := verifySource(ctx, w, budget)
		if er != nil || sha != row.SHA256 {
			return nil, errors.Join(ErrIntegrity, er)
		}
		c, _ := idx.ContentContainerAt(ci)
		if c.Entries == 0 {
			return nil, ErrInput
		}
		if er = idx.CompareContentContainer(ctx, ci, countedReader{ctx, file, budget}, c.Entries); er != nil {
			return nil, er
		}
	}
	totalChunks := 0
	for n := range work {
		w := &work[n]
		remaining := l.MaxResultBytes - s.AccountedBytes
		if remaining == 0 {
			return nil, ErrLimit
		}
		framingLimits := l
		framingLimits.MaxResultBytes = remaining
		var er error
		w.table, er = inspect(ctx, countedReader{ctx, sources[w.container].file, budget}, uint64(sources[w.container].local.Identity.Size), w.entry, framingLimits)
		if er != nil {
			return nil, er
		}
		chunks := max(uint64(1), w.table.count)
		if chunks > uint64(l.MaxTotalChunks-totalChunks) {
			return nil, ErrLimit
		}
		totalChunks += int(chunks)
	}
	volume, er := platform.InspectStorage(os.TempDir())
	if er != nil {
		return nil, er
	}
	overhead := max(uint64(64<<20), uint64(len(work))*(64<<10))
	if s.DecodedBytes > volume.AvailableBytes || overhead > volume.AvailableBytes-s.DecodedBytes {
		return nil, ErrLimit
	}
	for _, w := range work {
		if w.entry.LogicalSize > volume.MaxFileBytes {
			return nil, ErrLimit
		}
	}
	store, er = privatestore.New(privatestore.Profile{MaxFiles: l.MaxResources, MaxBytes: l.MaxOutputBytes}, "wim-verified-content")
	if er != nil {
		return nil, er
	}
	for _, w := range work {
		if er := ctx.Err(); er != nil {
			return nil, er
		}
		if w.table.count != 0 && w.entry.Location.Compression != 0 && provider == nil {
			provider, er = factory(ctx, l)
			if er != nil {
				return nil, er
			}
			host, er := platform.DetectHost(ctx)
			if er != nil {
				return nil, er
			}
			s.Provider = ProviderIdentity{provider.Identity(), string(host.ProcessArchitecture), string(host.NativeArchitecture), host.WindowsBuild}
		}
		f, name, er := store.Create(w.entry.LogicalSize)
		if er != nil {
			return nil, er
		}
		back, er := decodeResource(ctx, w, sources[w.container], l, budget, provider, f)
		er = errors.Join(er, f.Sync(), f.Close())
		if er != nil {
			return nil, er
		}
		data, er := store.Retain(name, w.entry.LogicalSize)
		if er != nil {
			return nil, joinIntegrity(er)
		}
		retained = append(retained, data)
		if er = budget.charge(back.Size); er != nil {
			return nil, er
		}
		if er = data.Verify(ctx, model.DigestSHA256, back.SHA256, back.SHA256); er != nil {
			return nil, joinIntegrity(er)
		}
		s.Backings = append(s.Backings, back)
	}
	seen := map[string]fingerprint{}
	for n := range s.Witnesses {
		w := &s.Witnesses[n]
		sha, sha256, er := hashInterval(ctx, retained[w.Backing], w.Entry.Location.LogicalOffset, w.Size, budget)
		if er != nil || sha != w.SHA1 {
			return nil, errors.Join(ErrIntegrity, er)
		}
		w.SHA256 = sha256
		if er = recordFingerprint(seen, w.SHA1, fingerprint{w.Size, sha256}); er != nil {
			return nil, er
		}
	}
	for _, w := range s.Witnesses {
		sha, sha256, er := hashInterval(ctx, retained[w.Backing], w.Entry.Location.LogicalOffset, w.Size, budget)
		if er != nil || sha != w.SHA1 || sha256 != w.SHA256 {
			return nil, errors.Join(ErrIntegrity, er)
		}
	}
	for n, data := range retained {
		w := s.Backings[n]
		if er = budget.charge(w.Size); er != nil {
			return nil, er
		}
		if er = data.Verify(ctx, model.DigestSHA256, w.SHA256, w.SHA256); er != nil {
			return nil, joinIntegrity(er)
		}
	}
	for n, w := range sources {
		sha, er := verifySource(ctx, w, budget)
		if er != nil || sha != w.receipt.SHA256 {
			return nil, errors.Join(ErrIntegrity, er)
		}
		s.Sources[n].Rehashed = true
	}
	finalSources = true
	if provider != nil {
		er = provider.Close()
		provider = nil
		if er != nil {
			return nil, er
		}
	}
	if er = store.Verify(ctx); er != nil {
		return nil, joinIntegrity(er)
	}
	if er = ctx.Err(); er != nil {
		return nil, er
	}
	s.ReadBytes = budget.used
	s.NonMetadataVerified = true
	c, er := seal(s)
	if er != nil {
		return nil, er
	}
	result = &Result{catalog: c, store: store, backings: retained}
	return result, nil
}
func verifySource(ctx context.Context, w sourceWork, b *readBudget) (string, error) {
	if e := b.charge(uint64(w.local.Identity.Size)); e != nil {
		return "", e
	}
	return localsource.Verify(ctx, w.file, w.local.Path, w.local.Identity, w.initial)
}

type fingerprint struct {
	size   uint64
	sha256 string
}

func recordFingerprint(seen map[string]fingerprint, sha1 string, f fingerprint) error {
	if previous, ok := seen[sha1]; ok && previous != f {
		return ErrConflict
	}
	seen[sha1] = f
	return nil
}
func hashInterval(ctx context.Context, r io.ReaderAt, off, size uint64, b *readBudget) (string, string, error) {
	h1, h256 := sha1.New(), sha256.New()
	buf := make([]byte, 64<<10)
	reader := countedReader{ctx, r, b}
	for pos := uint64(0); pos < size; {
		part := buf[:min(uint64(len(buf)), size-pos)]
		if e := read(ctx, reader, off+size, off+pos, part); e != nil {
			return "", "", e
		}
		h1.Write(part)
		h256.Write(part)
		pos += uint64(len(part))
	}
	return hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h256.Sum(nil)), nil
}
func decodeResource(ctx context.Context, w resourceWork, source sourceWork, l Limits, budget *readBudget, provider codec, f *os.File) (BackingReceipt, error) {
	back := BackingReceipt{Payload: source.local.Identity, SourceSHA256: source.receipt.SHA256, Header: source.receipt.Header, Entry: w.entry, Size: w.entry.LogicalSize}
	h := sha256.New()
	out := io.MultiWriter(f, h)
	reader := countedReader{ctx, source.file, budget}
	write := func(b []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		n, e := out.Write(b)
		if n != len(b) {
			e = errors.Join(e, io.ErrShortWrite)
		}
		return e
	}
	if w.table.count == 0 {
		buf := make([]byte, 64<<10)
		for pos := uint64(0); pos < w.entry.LogicalSize; {
			part := buf[:min(uint64(len(buf)), w.entry.LogicalSize-pos)]
			if e := read(ctx, reader, uint64(source.local.Identity.Size), w.entry.Descriptor.Offset+pos, part); e != nil {
				return back, e
			}
			if e := write(part); e != nil {
				return back, e
			}
			pos += uint64(len(part))
		}
		back.StoredChunks = 1
		back.Chunks = 1
	} else {
		var maxInput, maxOutput uint64
		for _, c := range w.table.chunks {
			maxInput = max(maxInput, c.size)
			if c.size != c.logical {
				maxOutput = max(maxOutput, c.logical)
			}
		}
		// Allocate exactly one reusable input/output pair after all declarations and
		// remaining per-call/aggregate bounds were checked. Prior work's pair is
		// released when this function returns; no chunk-sized result is retained.
		if maxInput+maxOutput > uint64(l.MaxBufferBytes) {
			return back, ErrLimit
		}
		input := make([]byte, int(maxInput))
		output := make([]byte, int(maxOutput))
		for _, c := range w.table.chunks {
			if e := ctx.Err(); e != nil {
				return back, e
			}
			in := input[:c.size]
			if e := read(ctx, reader, uint64(source.local.Identity.Size), c.offset, in); e != nil {
				return back, e
			}
			decoded := in
			if c.size != c.logical {
				if provider == nil {
					return back, ErrUnsupported
				}
				decoded = output[:c.logical]
				if e := provider.DecodeInto(ctx, in, decoded); e != nil {
					return back, e
				}
				if e := ctx.Err(); e != nil {
					return back, e
				}
				back.CompressedChunks++
			} else {
				back.StoredChunks++
			}
			if e := write(decoded); e != nil {
				return back, e
			}
			back.Chunks++
		}
	}
	info, e := f.Stat()
	if e != nil || info.Size() != int64(back.Size) {
		return back, errors.Join(ErrIntegrity, e)
	}
	back.SHA256 = hex.EncodeToString(h.Sum(nil))
	return back, nil
}
