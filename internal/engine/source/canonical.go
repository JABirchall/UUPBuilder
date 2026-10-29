package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

type Canonical struct{}

func (Canonical) Match(inv metadata.Inventory) (Match, error) {
	var out Match
	for _, im := range inv.Images {
		if im.Architecture != inv.Source.Architecture || im.Architecture != "x86" || im.Edition != "Professional" || im.InstallationType != "Client" || im.Build != "10.0.19041.1" {
			continue
		}
		if out.Matched {
			return Match{}, ErrInput
		}
		out = Match{true, "canonical-client-19041", im.Index, im.Edition, im.Build}
	}
	return out, nil
}
func (c Canonical) Recipe(inv metadata.Inventory, settings model.ResolvedSettings) (Recipe, error) {
	m, e := c.Match(inv)
	if e != nil || !m.Matched {
		return Recipe{}, ErrInput
	}
	return recipe(inv.Source, inv.Manifest.Digest, m), nil
}
func recipe(s model.SourceIdentity, manifest string, m Match) Recipe {
	rule := sha256.Sum256([]byte("canonical-client-19041/v1: inspected Client Professional x86 10.0.19041.1; exact raw metadata; single-image standard raw WIM; content by complete SHA1 size SHA256 and provenance; table stream references include every hardlink name; no servicing"))
	return Recipe{Family: m.Family, RuleDigest: hex.EncodeToString(rule[:]), Source: s, ManifestDigest: manifest, Edition: m.Edition, BaselineVersion: m.BaselineVersion, ImageIndex: m.ImageIndex, Requirements: []Requirement{{"reconstruct", "go-standard-wim", "raw-source-preserving-v1"}, {"inspect", "installed-wimgapi", "read-existing-load-xml-v1"}}, Gaps: []string{"boot/setup roles unproved", "native ACL/EA/ADS/hardlink/reparse preservation unproved", "serviced catalog build requires servicing proof", "Normalize/Assembler verified-toolchain/transaction integration incomplete"}}
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func bytesDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func identityCost(p model.PayloadIdentity) uint64 {
	return uint64(len(p.Provenance.Source) + len(p.Provenance.Name) + len(p.Digest.Algorithm) + len(p.Digest.Value) + len(p.Encryption.Method) + len(p.Encryption.Fingerprint))
}
func validManifestInput(in Inputs, l Limits) error {
	if len(in.Manifest.Payloads) > 4096 || len(in.Manifest.Queries) > 64 || len(in.Files) > 64 {
		return ErrLimit
	}
	stringsBytes := uint64(len(in.Manifest.Source.UpdateID) + len(in.Manifest.Source.BuildLabel) + len(in.Manifest.Source.Language) + len(in.Manifest.Source.Architecture))
	for _, s := range []string{in.Manifest.Source.UpdateID, in.Manifest.Source.BuildLabel, string(in.Manifest.Source.Architecture), in.Manifest.Source.Language, in.Manifest.Digest} {
		if len(s) > 4096 {
			return ErrLimit
		}
	}
	chargePayload := func(p model.Payload) error {
		for _, s := range []string{p.Identity.Provenance.Source, p.Identity.Provenance.Name, string(p.Identity.Digest.Algorithm), p.Identity.Digest.Value, p.Identity.Encryption.Method, p.Identity.Encryption.Fingerprint, p.Destination} {
			if len(s) > 4096 {
				return ErrLimit
			}
		}
		if strings.Count(p.Destination, "/")+strings.Count(p.Destination, `\`) >= 64 {
			return ErrLimit
		}
		stringsBytes += identityCost(p.Identity) + uint64(len(p.Destination))
		return nil
	}
	for _, p := range in.Manifest.Payloads {
		if e := chargePayload(p); e != nil {
			return e
		}
	}
	projections := 0
	for _, q := range in.Manifest.Queries {
		if len(q.UpdateID) > 4096 || len(q.Language) > 4096 || len(q.Edition) > 4096 || len(q.Projection) > 4096-projections {
			return ErrLimit
		}
		projections += len(q.Projection)
		stringsBytes += uint64(len(q.UpdateID) + len(q.Language) + len(q.Edition))
		for _, p := range q.Projection {
			if e := chargePayload(p); e != nil {
				return e
			}
		}
	}
	for _, f := range in.Files {
		if e := chargePayload(model.Payload{Identity: f.Identity}); e != nil {
			return e
		}
		if len(f.Path) > 32768 {
			return ErrLimit
		}
		stringsBytes += uint64(len(f.Path))
	}
	if stringsBytes > 16<<20 || stringsBytes*8 > l.MaxResultBytes {
		return ErrLimit
	}
	if in.Manifest.Validate() != nil {
		return ErrInput
	}
	return nil
}

func BindCanonical(ctx context.Context, in Inputs, limits Limits) (*BoundRecipe, error) {
	if e := contextValid(ctx); e != nil {
		return nil, e
	}
	l, e := bounds(limits)
	if e != nil {
		return nil, e
	}
	if e = validManifestInput(in, l); e != nil {
		return nil, e
	}
	if in.Index == nil || in.Metadata == nil || in.Oracle == nil || in.References == nil {
		return nil, ErrInput
	}
	index, oracle, view := in.Index.ContentClaim(), in.Oracle.Claim(), in.References.Claim()
	receipt := in.Metadata.Receipt()
	if !index.Verified || !oracle.Verified || !view.Verified || !view.ReferenceClosure || index.Source != in.Manifest.Source || index.ManifestDigest != in.Manifest.Digest || oracle.Receipt != receipt || view.Oracle != oracle || !in.Index.MatchesMetadataReceipt(receipt) {
		return nil, ErrInput
	}
	if view.References != oracle.References || view.References > l.MaxReferences || oracle.Summary.Entries > l.MaxEntries {
		return nil, ErrLimit
	}
	// The original oracle's conservative accounting bounds its nested Snapshot
	// before cloning. Exact reference/witness strings are charged separately.
	// Reserve the bounded snapshot, stream-count map and worst original-record
	// JSON witness scratch before either cloning or serializing any record.
	accounted := oracle.Summary.AccountedBytes + receipt.Size*2 + uint64(oracle.References)*128 + receipt.Header.XML.Size*16 + 4096
	if accounted > l.MaxResultBytes {
		return nil, ErrLimit
	}
	resources, e := bindReferences(ctx, in, view, l, &accounted)
	if e != nil {
		return nil, e
	}
	if e = in.References.CheckLive(); e != nil {
		return nil, e
	}
	if receipt.Size*2 > l.MaxReadBytes || uint64(receipt.Payload.Size)*2+receipt.Header.XML.Size > l.MaxReadBytes-receipt.Size*2 {
		return nil, ErrLimit
	}
	if e = verifyMetadata(ctx, in.Metadata, receipt); e != nil {
		return nil, e
	}
	snap := in.Oracle.Snapshot()
	counts := make(map[string]uint32, oracle.References)
	var osPaths [3]bool
	for _, g := range snap.Hardlinks {
		if !g.Consistent {
			return nil, ErrInput
		}
	}
	// The primary blob format counts stream references over file names: one inode
	// contributes its link count. Every original dentry's stream is present here,
	// so counting original records preserves that count without coalescing files.
	for _, en := range snap.Entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if en.PathValid {
			for n, path := range []string{"/Windows/System32/ntoskrnl.exe", "/Windows/System32/config/SOFTWARE", "/Windows/System32/config/SYSTEM"} {
				if strings.EqualFold(en.Path, path) {
					for _, stream := range en.Streams {
						if en.Attributes&0x410 == 0 && stream.Kind == "data" && stream.SHA1 != "0000000000000000000000000000000000000000" {
							osPaths[n] = true
						}
					}
				}
			}
		}
		for _, s := range en.Streams {
			if s.SHA1 == "0000000000000000000000000000000000000000" {
				continue
			}
			if counts[s.SHA1] == ^uint32(0) {
				return nil, ErrLimit
			}
			counts[s.SHA1]++
		}
	}
	for n := 1; n < len(resources); n++ {
		count := counts[resources[n].identity.SHA1]
		if count == 0 {
			return nil, ErrInput
		}
		resources[n].identity.References = count
		delete(counts, resources[n].identity.SHA1)
	}
	if len(counts) != 0 {
		return nil, ErrInput
	}
	if !osPaths[0] || !osPaths[1] || !osPaths[2] {
		return nil, ErrInput
	}
	xml, original, inv, e := selectedXML(ctx, in, receipt, l)
	if e != nil {
		return nil, e
	}
	m, e := (Canonical{}).Match(inv)
	if e != nil || !m.Matched || m.ImageIndex != int(receipt.Entry.ImageIndex) {
		return nil, ErrInput
	}
	d := Descriptor{Recipe: recipe(in.Manifest.Source, in.Manifest.Digest, m), Index: index, Metadata: receipt, Oracle: oracle, ReferenceDigest: view.Digest, WIMDigest: view.WIMDigest, CABDigest: view.CABDigest, OriginalXMLSHA256: original, OutputXMLSHA256: bytesDigest(xml), Resources: len(resources), AccountedBytes: accounted, PermittedOperations: []string{"read original metadata and WIM/CAB bytes", "write standard WIM framing in owned private storage", "independent complete byte verification", "optional installed WIMGAPI existing/read image-count load XML"}, NativeCandidate: "installed-system wimgapi.dll; read-only; non-elevated; stop first failure"}
	for _, r := range resources {
		d.ResourceBytes += r.identity.Size
	}
	d.Expected = expectedFacts(snap)
	d.RecipeDigest = digest(d.Recipe)
	d.XMLBytes = uint64(len(xml))
	d.ResourceDigest = digest(resources)
	d.ProofDigest = digest(d)
	result := &BoundRecipe{state: d, metadata: in.Metadata, view: in.References, resources: resources, xml: xml, flags: receipt.Header.Flags & 0x80}
	if e = verifyMetadata(ctx, in.Metadata, receipt); e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = result.CheckLive(); e != nil {
		return nil, e
	}
	return result, nil
}

// Select each kind independently: early hardlinks must not crowd required OS,
// reparse, opaque or named-stream witnesses out of the bounded descriptor.
func expectedFacts(s wimmeta.Snapshot) []PathFact {
	var result []PathFact
	seen := map[int]bool{}
	add := func(n int) {
		if n < 0 || n >= len(s.Entries) || seen[n] || len(result) >= 24 {
			return
		}
		seen[n] = true
		en := s.Entries[n]
		security := ""
		if int(en.SecurityID) < len(s.Security) {
			security = bytesDigest(s.Security[en.SecurityID].Raw)
		}
		result = append(result, PathFact{en.Path, en.Offset, en.Attributes, en.SecurityID, security, en.HardlinkID, en.ReparseTag, len(en.Streams), len(en.Tags), digest(en)})
	}
	add(0)
	for _, path := range []string{"/Windows/System32/ntoskrnl.exe", "/Windows/System32/config/SOFTWARE", "/Windows/System32/config/SYSTEM"} {
		for n, en := range s.Entries {
			if strings.EqualFold(en.Path, path) {
				add(n)
				break
			}
		}
	}
	predicates := []func(wimmeta.Entry) bool{func(e wimmeta.Entry) bool { return e.ReparseTag != 0 }, func(e wimmeta.Entry) bool { return len(e.Tags) > 0 }, func(e wimmeta.Entry) bool { return len(e.Streams) > 1 }, func(e wimmeta.Entry) bool { return len(e.ShortName) > 0 }, func(e wimmeta.Entry) bool {
		return e.Attributes&16 == 0 && len(e.Streams) == 1 && e.Streams[0].SizeKnown && e.Streams[0].Size == 0
	}}
	for _, predicate := range predicates {
		for n, en := range s.Entries {
			if predicate(en) {
				add(n)
				break
			}
		}
	}
	for _, g := range s.Hardlinks {
		if g.Consistent && len(g.Entries) > 1 {
			for _, n := range g.Entries[:min(2, len(g.Entries))] {
				add(n)
			}
			break
		}
	}
	return result
}
