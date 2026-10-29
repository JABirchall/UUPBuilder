package cabindex

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabformat"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

type dataProvider interface {
	Identity() ProviderIdentity
	Extract(context.Context, io.ReaderAt, uint64, cabformat.Inventory, *memberSink, *runBudget) error
	Close() error
}
type providerFactory func(context.Context) (dataProvider, error)
type sourceWork struct {
	resource    metadata.LocalResource
	file        *os.File
	initial     os.FileInfo
	sha         string
	table       cabformat.Inventory
	observation int
}
type runBudget struct {
	limits                                             Limits
	nativeUsed, nativePeak, nativeTotal, providerReads uint64
}

func build(ctx context.Context, m model.PayloadManifest, files []metadata.LocalResource, o *wimmeta.Oracle, l Limits, factory providerFactory) (result *Result, runErr error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := bounds(l)
	if e != nil {
		return nil, e
	}
	if l.MaxBufferBytes < 64<<10 {
		return nil, ErrLimit
	}
	claim := o.Claim()
	if !claim.Verified || claim.Receipt.Source != m.Source || claim.Receipt.ManifestDigest != m.Digest {
		return nil, ErrInput
	}
	if len(m.Payloads) > l.MaxManifestPayloads || len(m.Queries) > l.MaxQueries || len(files) > l.MaxSources || claim.References > l.MaxReferences {
		return nil, ErrLimit
	}
	projection := 0
	for _, q := range m.Queries {
		if len(q.Projection) > l.MaxProjectionPayloads-projection {
			return nil, ErrLimit
		}
		projection += len(q.Projection)
	}
	manifestBytes, e := boundedManifestBytes(m, l.MaxManifestBytes, l.MaxVariableBytes)
	if e != nil {
		return nil, e
	}
	initialCharge := manifestBytes*8 + uint64(claim.References)*256 + uint64(len(m.Payloads)+projection)*16384 + uint64(len(m.Queries))*256 + 4096
	if initialCharge > l.MaxResultBytes {
		return nil, ErrLimit
	}
	if m.Validate() != nil {
		return nil, ErrInput
	}

	m = model.PayloadManifest{Source: m.Source, Payloads: slices.Clone(m.Payloads), Queries: model.CloneSourceQueries(m.Queries), Digest: m.Digest}
	// Validate accepts a permutation with the same canonical digest. Restore
	// canonical destination order before choosing the first necessary source.
	slices.SortFunc(m.Payloads, func(a, b model.Payload) int { return strings.Compare(a.Destination, b.Destination) })
	files = slices.Clone(files)
	s := Snapshot{Schema: 1, Oracle: claim, AccountedBytes: initialCharge}
	refs := make(map[string]int, claim.References)
	for n := 0; n < claim.References; n++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		c, ok := o.ReferenceClaimAt(n)
		if !ok {
			return nil, ErrInput
		}
		refs[c.SHA1] = len(s.References)
		s.References = append(s.References, Resolution{Original: c})
	}
	supplied := map[model.PayloadIdentity]metadata.LocalResource{}
	var inputTotal uint64
	for _, f := range files {
		// Supplied identities are separate caller input. Bound their strings
		// before validation can format an error or normalization can allocate.
		for _, value := range [...]string{string(f.Identity.Digest.Algorithm), f.Identity.Digest.Value, f.Identity.Provenance.Source, f.Identity.Provenance.Name, f.Identity.Encryption.Method, f.Identity.Encryption.Fingerprint} {
			if len(value) > l.MaxVariableBytes {
				return nil, ErrLimit
			}
		}
		bound := false
		for _, p := range m.Payloads {
			if p.Identity == f.Identity {
				bound = true
				break
			}
		}
		if !bound {
			return nil, ErrInput
		}
		if f.Identity.Validate() != nil || f.Identity.Encryption.Method != "" || f.Identity.Size < 36 || !strings.EqualFold(strings.TrimSpace(f.Identity.Provenance.Name), f.Identity.Provenance.Name) || !strings.HasSuffix(strings.ToLower(f.Identity.Provenance.Name), ".cab") {
			return nil, ErrInput
		}
		if _, ok := supplied[f.Identity]; ok {
			return nil, ErrInput
		}
		if uint64(f.Identity.Size) > l.MaxSourceBytes || uint64(f.Identity.Size) > l.MaxTotalSourceBytes-inputTotal {
			return nil, ErrLimit
		}
		inputTotal += uint64(f.Identity.Size)
		supplied[f.Identity] = f
	}
	var work []sourceWork
	var provider dataProvider
	var store *privateStore
	var artifacts []*ContentArtifact
	sourcesFinal := false
	defer func() {
		if provider != nil {
			runErr = errors.Join(runErr, provider.Close())
		}
		for _, w := range work {
			if !sourcesFinal {
				sha, err := localsource.Verify(ctx, w.file, w.resource.Path, w.resource.Identity, w.initial)
				if err != nil || sha != w.sha {
					runErr = errors.Join(runErr, ErrIntegrity, err)
				}
			}
			runErr = errors.Join(runErr, w.file.Close())
		}
		if runErr != nil {
			for _, a := range artifacts {
				runErr = errors.Join(runErr, a.close())
			}
			if store != nil {
				runErr = errors.Join(runErr, store.close())
			}
			result = nil
		}
	}()
	var metadataBytes uint64
	totalMembers := 0
	totalFolders, totalBlocks := 0, 0
	// Manifest order is canonical and independent of caller order. All supplied
	// directories are validated against aggregate bounds before loading the DLL.
	for _, p := range m.Payloads {
		if !strings.HasSuffix(strings.ToLower(p.Identity.Provenance.Name), ".cab") {
			continue
		}
		row := SourceObservation{Payload: p.Identity, Status: "not-selected"}
		f, ok := supplied[p.Identity]
		s.Sources = append(s.Sources, row)
		if !ok {
			continue
		}
		delete(supplied, p.Identity)
		file, initial, e := localsource.Open(f.Path, f.Identity)
		if e != nil {
			return nil, e
		}
		w := sourceWork{resource: f, file: file, initial: initial, observation: len(s.Sources) - 1}
		work = append(work, w)
		v := &work[len(work)-1]
		v.sha, e = localsource.Verify(ctx, file, f.Path, f.Identity, initial)
		if e != nil {
			return nil, e
		}
		if totalMembers == l.MaxMembers || totalFolders == l.MaxFolders || totalBlocks == l.MaxBlocks {
			return nil, ErrLimit
		}
		remaining := l.MaxMetadataBytes - metadataBytes
		declaredRemaining := l.MaxDeclaredBytes - s.DeclaredBytes
		resultRemaining := l.MaxResultBytes - s.AccountedBytes
		// Zero means the framing parser's default allowance, not an exhausted
		// caller budget. Refuse before handing that sentinel to Inspect.
		if remaining == 0 || declaredRemaining == 0 || resultRemaining == 0 {
			return nil, ErrLimit
		}
		v.table, e = cabformat.Inspect(ctx, file, uint64(f.Identity.Size), cabformat.Limits{MaxSourceBytes: l.MaxSourceBytes, MaxMemberBytes: l.MaxMemberBytes, MaxDecodedBytes: declaredRemaining, MaxMetadataBytes: min(remaining, 32<<20), MaxMembers: min(l.MaxMembers-totalMembers, 65535), MaxFolders: l.MaxFolders - totalFolders, MaxBlocks: l.MaxBlocks - totalBlocks, MaxNameBytes: l.MaxNameBytes, MaxDirectoryBytes: min(resultRemaining, 128<<20)})
		if e != nil {
			return nil, e
		}
		metadataBytes += v.table.MetadataBytes
		for _, member := range v.table.Members {
			if member.Size > l.MaxDiskBytes {
				return nil, ErrLimit
			}
		}
		if len(v.table.Members) > l.MaxMembers-totalMembers || v.table.FolderBytes > l.MaxDeclaredBytes-s.DeclaredBytes {
			return nil, ErrLimit
		}
		totalMembers += len(v.table.Members)
		totalFolders += len(v.table.Compressions)
		totalBlocks += v.table.Blocks
		s.DeclaredBytes += v.table.FolderBytes
		charge := uint64(len(v.table.Members))*1024 + uint64(len(v.table.Compressions))*64
		if charge > l.MaxResultBytes-s.AccountedBytes {
			return nil, ErrLimit
		}
		s.AccountedBytes += charge
		for _, c := range v.table.Compressions {
			if c != 0 && c != 1 && (c&0xff == 3 && c>>8 >= 15 && c>>8 <= 21) == false {
				return nil, ErrUnsupported
			}
		}
		obs := &s.Sources[v.observation]
		obs.SourceSHA256 = v.sha
		obs.Status = "validated-pending"
		obs.CabinetBytes = v.table.CabinetBytes
		obs.TrailingBytes = v.table.TrailingBytes
		obs.DeclaredBytes = v.table.DecodedBytes
		obs.Members = len(v.table.Members)
	}
	if len(supplied) != 0 {
		return nil, ErrInput
	}
	pending := 0
	for _, r := range s.References {
		if r.Original.Witnesses == 0 {
			pending++
		}
	}
	budget := &runBudget{limits: l}
	seen := map[string]fingerprint{}
	for _, w := range work {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		row := &s.Sources[w.observation]
		if pending == 0 {
			row.Status = "closure-satisfied"
			continue
		}
		if provider == nil {
			provider, e = factory(ctx)
			if e != nil {
				return nil, e
			}
			s.Provider = provider.Identity()
			if s.Provider.DLL.Name == "" || len(s.Provider.DLL.SHA256) != 64 || s.Provider.DLL.Size <= 0 {
				return nil, ErrIntegrity
			}
			store, e = newPrivateStore()
			if e != nil {
				return nil, e
			}
		}
		sink := &memberSink{ctx: ctx, store: store, source: w, limits: l, state: &s, refs: refs, seen: seen, artifacts: &artifacts, pending: &pending}
		if e = provider.Extract(ctx, w.file, uint64(w.resource.Identity.Size), w.table, sink, budget); e != nil {
			return nil, errors.Join(e, sink.abort())
		}
		if e = sink.complete(); e != nil {
			return nil, errors.Join(e, sink.abort())
		}
		row = &s.Sources[w.observation]
		row.Status = "attempted"
		row.DecodedBytes = sink.observed
		row.DecodedMembers = sink.next
		row.Matches = sink.matches
	}
	for _, w := range work {
		sha, e := localsource.Verify(ctx, w.file, w.resource.Path, w.resource.Identity, w.initial)
		if e != nil || sha != w.sha {
			return nil, errors.Join(ErrIntegrity, e)
		}
	}
	sourcesFinal = true
	for i := range work {
		s.Sources[work[i].observation].SourceRehashed = true
	}
	for n, a := range artifacts {
		if a.Binding() != s.Oracle {
			return nil, ErrInput
		}
		if e := a.verify(ctx, s.Witnesses[n], l.MaxBufferBytes); e != nil {
			return nil, e
		}
	}
	if store != nil {
		if e := store.verify(ctx); e != nil {
			return nil, e
		}
	}
	for _, r := range s.References {
		if r.Original.Witnesses == 0 && len(r.Witnesses) == 0 {
			s.Unresolved = append(s.Unresolved, Missing{r.Original.SHA1})
		}
	}
	s.ReferenceClosure = len(s.Unresolved) == 0
	s.ProviderReadBytes = budget.providerReads
	s.NativePeakBytes = budget.nativePeak
	s.NativeTotalBytes = budget.nativeTotal
	c, e := seal(s)
	if e != nil {
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	result = &Result{catalog: c, store: store, artifacts: artifacts}
	return result, nil
}

// Measure caller strings before canonical validation can clone/serialize them.
// A location is never retained in the catalog; manifest identities remain exact.
func boundedManifestBytes(m model.PayloadManifest, limit uint64, variable int) (uint64, error) {
	var total uint64
	add := func(values ...string) bool {
		for _, v := range values {
			if len(v) > variable || uint64(len(v)) > limit-total {
				return false
			}
			total += uint64(len(v))
		}
		return true
	}
	payload := func(p model.Payload) bool {
		if strings.Count(p.Destination, "/")+strings.Count(p.Destination, `\`) > 63 {
			return false
		}
		i := p.Identity
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
