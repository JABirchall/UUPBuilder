package engine

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"unicode/utf16"

	"uupbuilder/internal/metadata/wimmeta"
	platform "uupbuilder/internal/platform/windows"
)

type ComparisonMismatch struct {
	Path, Field, Expected, Observed string
	ExpectedRaw, ObservedRaw        []byte
}
type ComparisonEvidence struct {
	Source                           ExpectationDescriptor
	Destination                      platform.TreeIdentity
	InitialInventory, FinalInventory platform.TreeInventory
	Mismatches                       []ComparisonMismatch
	Unresolved                       []FieldRequirement
	EntriesObserved, StreamsCompared int
	ReadBytes, AccountedBytes        uint64
	Complete                         bool
	Limitations                      []string
}
type preservationObservationPort interface {
	Identity() platform.TreeIdentity
	CheckObservationLive(context.Context) error
	ObserveInventory(context.Context, platform.TreeLimits) (platform.TreeInventory, error)
	Observe(context.Context, string, platform.MetadataLimits) (platform.MetadataObservation, error)
	ReadOwnedAt(context.Context, string, string, []byte, int64) (int, error)
}
type PreservationComparison struct {
	expected *SourceExpectations
	port     preservationObservationPort
	state    ComparisonEvidence
	limits   ComparisonLimits
}

// ComparePreservation consumes only the existing created-entry OwnedTree. It
// returns component comparison evidence, never native descendant authority.
func ComparePreservation(ctx context.Context, x *SourceExpectations, t *platform.OwnedTree, l ComparisonLimits) (*PreservationComparison, error) {
	if t == nil {
		return nil, ErrInput
	}
	return comparePreservation(ctx, x, t, l)
}
func (r *PreservationComparison) live(ctx context.Context) error {
	if r == nil || r.port == nil || ctx == nil {
		return ErrInput
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := r.expected.CheckLive(); e != nil {
		return e
	}
	if r.port.Identity() != r.state.Destination {
		return ErrInput
	}
	return r.port.CheckObservationLive(ctx)
}
func evidenceCost(v ComparisonEvidence) uint64 {
	n := uint64(8192)
	r := v.Source.Oracle.Receipt
	for _, s := range []string{v.Source.ProofDigest, v.Source.Oracle.Digest, r.Source.UpdateID, r.Source.BuildLabel, string(r.Source.Architecture), r.Source.Language, r.ManifestDigest, r.IndexDigest, r.SourceSHA256, r.Payload.Provenance.Source, r.Payload.Provenance.Name, string(r.Payload.Digest.Algorithm), r.Payload.Digest.Value, r.Payload.Encryption.Method, r.Payload.Encryption.Fingerprint, r.Header.GUID, r.Entry.SHA1, r.Entry.Kind, r.SHA1, r.SHA256, r.Codec.Name, r.Codec.SHA256} {
		n += uint64(len(s)) * 2
	}
	for _, id := range []platform.TreeIdentity{v.Destination, v.InitialInventory.Tree, v.FinalInventory.Tree} {
		n += uint64(len(id.Workspace.Path)+len(id.Workspace.JobID)+len(id.Workspace.Token)+len(id.RelativePath)+len(id.OperationID)+len(id.SourceDigest)) * 2
	}
	for _, inventory := range []platform.TreeInventory{v.InitialInventory, v.FinalInventory} {
		n += uint64(len(inventory.Entries)) * 256
		for _, entry := range inventory.Entries {
			n += uint64(len(entry.Path)+len(entry.Status)) * 2
		}
	}
	for _, s := range v.Limitations {
		n += uint64(len(s))*2 + 32
	}
	for _, m := range v.Mismatches {
		n += uint64(512 + (len(m.Path)+len(m.Field)+len(m.Expected)+len(m.Observed)+len(m.ExpectedRaw)+len(m.ObservedRaw))*2)
	}
	for _, q := range v.Unresolved {
		n += uint64(512 + (len(q.Path)+len(q.Field)+len(q.Detail))*2)
	}
	return n
}
func (r *PreservationComparison) Evidence(ctx context.Context, allowance uint64) (ComparisonEvidence, error) {
	if e := r.live(ctx); e != nil {
		return ComparisonEvidence{}, e
	}
	if evidenceCost(r.state) > allowance || allowance > 512<<20 {
		return ComparisonEvidence{}, ErrLimit
	}
	v := r.state
	v.InitialInventory.Entries = slices.Clone(v.InitialInventory.Entries)
	v.FinalInventory.Entries = slices.Clone(v.FinalInventory.Entries)
	v.Mismatches = slices.Clone(v.Mismatches)
	for j := range v.Mismatches {
		v.Mismatches[j].ExpectedRaw = slices.Clone(v.Mismatches[j].ExpectedRaw)
		v.Mismatches[j].ObservedRaw = slices.Clone(v.Mismatches[j].ObservedRaw)
	}
	v.Unresolved = slices.Clone(v.Unresolved)
	v.Limitations = slices.Clone(v.Limitations)
	if e := r.live(ctx); e != nil {
		return ComparisonEvidence{}, e
	}
	return v, nil
}
func (r *PreservationComparison) Serialize(ctx context.Context, allowance uint64) ([]byte, error) {
	if e := r.live(ctx); e != nil {
		return nil, e
	}
	// JSON escaping/base64/numbers and encoder scratch are reserved before
	// encoding, including the private encoder's full-value buffering.
	bound := evidenceCost(r.state)*8 + 8192
	if bound > allowance || bound > r.limits.MaxSerializationBytes {
		return nil, ErrLimit
	}
	b, e := json.Marshal(r.state)
	if e != nil {
		return nil, e
	}
	if uint64(len(b)) > allowance {
		return nil, ErrLimit
	}
	if e = r.live(ctx); e != nil {
		return nil, e
	}
	return b, nil
}

type comparisonRun struct {
	ctx           context.Context
	x             *SourceExpectations
	p             preservationObservationPort
	l             ComparisonLimits
	v             ComparisonEvidence
	nativeStreams int
}

func (c *comparisonRun) charge(n uint64) error {
	if e := c.ctx.Err(); e != nil {
		return e
	}
	if n > c.l.MaxResultBytes-c.v.AccountedBytes {
		return ErrLimit
	}
	c.v.AccountedBytes += n
	return nil
}
func (c *comparisonRun) mismatch(path, field, want, got string, wr, gr []byte) error {
	if len(c.v.Mismatches) >= c.l.MaxRequirements {
		return ErrLimit
	}
	for _, s := range []string{path, field, want, got} {
		if len(s) > c.l.MaxStringBytes {
			return ErrLimit
		}
	}
	if e := c.charge(uint64(512 + (len(path)+len(field)+len(want)+len(got)+len(wr)+len(gr))*2)); e != nil {
		return e
	}
	c.v.Mismatches = append(c.v.Mismatches, ComparisonMismatch{path, field, want, got, slices.Clone(wr), slices.Clone(gr)})
	return nil
}
func (c *comparisonRun) unknown(path, field, detail string) error {
	if len(c.v.Unresolved) >= c.l.MaxRequirements || len(path) > c.l.MaxStringBytes || len(field) > c.l.MaxStringBytes || len(detail) > c.l.MaxStringBytes {
		return ErrLimit
	}
	if e := c.charge(uint64(512 + (len(path)+len(field)+len(detail))*2)); e != nil {
		return e
	}
	c.v.Unresolved = append(c.v.Unresolved, FieldRequirement{Entry: -1, Path: path, Field: field, Detail: detail})
	return nil
}
func (c *comparisonRun) inventory() (platform.TreeInventory, error) {
	read, result := c.l.MaxReadBytes-c.v.ReadBytes, c.l.MaxResultBytes-c.v.AccountedBytes
	if read == 0 || result == 0 {
		return platform.TreeInventory{}, ErrLimit
	}
	l := platform.TreeLimits{MaxEntries: min(c.l.MaxEntries, 4096), MaxDepth: 32, MaxReadBytes: min(read, 16<<20), MaxResultBytes: min(result, 4<<20)}
	v, e := c.p.ObserveInventory(c.ctx, l)
	if e != nil {
		return v, e
	}
	if len(v.Entries) > c.l.MaxEntries+1 || v.ReadBytes > read || v.AccountedBytes > result {
		return v, ErrLimit
	}
	if e = c.charge(v.AccountedBytes + uint64(len(v.Entries))*256); e != nil {
		return v, e
	}
	c.v.ReadBytes += v.ReadBytes
	for _, en := range v.Entries {
		if len(en.Path) > c.l.MaxStringBytes {
			return v, ErrLimit
		}
	}
	return v, nil
}

const comparisonMetadataReserve = uint64(64<<10)*12 + 512*128 + 4096

func (c *comparisonRun) observe(name string) (platform.MetadataObservation, error) {
	remaining := min(256, c.l.MaxStreams-c.nativeStreams)
	if remaining <= 0 {
		return platform.MetadataObservation{}, ErrLimit
	}
	if e := c.charge(comparisonMetadataReserve); e != nil {
		return platform.MetadataObservation{}, e
	}
	read := c.l.MaxReadBytes - c.v.ReadBytes
	if read == 0 {
		return platform.MetadataObservation{}, ErrLimit
	}
	o, e := c.p.Observe(c.ctx, name, platform.MetadataLimits{MaxBufferBytes: 64 << 10, MaxStreams: remaining, MaxEAs: 256, MaxReadBytes: min(read, 4<<20), MaxResultBytes: comparisonMetadataReserve})
	if e != nil {
		return o, e
	}
	if o.ReadBytes > read || len(o.NamedStreams) > remaining || len(o.ExtendedAttributes) > 256 {
		return o, ErrLimit
	}
	c.nativeStreams += len(o.NamedStreams)
	c.v.ReadBytes += o.ReadBytes
	var cost uint64
	for _, f := range []platform.MetadataField{o.Basic, o.FileID, o.Security, o.SACL, o.Streams, o.EAs, o.Reparse} {
		if len(f.Raw) > 64<<10 || len(f.Detail) > c.l.MaxStringBytes {
			return o, ErrLimit
		}
		cost += uint64(len(f.Raw)*2 + len(f.Detail)*2)
	}
	for _, s := range o.NamedStreams {
		if len(s.Name)*2 > c.l.MaxStringBytes {
			return o, ErrLimit
		}
		cost += uint64(128 + len(s.Name)*4)
	}
	for _, ea := range o.ExtendedAttributes {
		cost += uint64(128 + (len(ea.Name)+len(ea.Value))*2)
	}
	if cost > comparisonMetadataReserve {
		return o, ErrLimit
	}
	return o, nil
}

func comparePreservation(ctx context.Context, x *SourceExpectations, p preservationObservationPort, limits ComparisonLimits) (*PreservationComparison, error) {
	if ctx == nil || p == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := x.CheckLive(); e != nil {
		return nil, e
	}
	l, e := comparisonBounds(limits)
	if e != nil {
		return nil, e
	}
	id := p.Identity()
	if id.SourceDigest != x.state.ProofDigest || id.Root.FileIndex == 0 || id.OperationID == "" {
		return nil, ErrInput
	}
	if len(x.entries) > l.MaxEntries || len(x.security) > l.MaxSecurity || x.state.Oracle.Summary.Streams > l.MaxStreams {
		return nil, ErrLimit
	}
	if x.state.Oracle.Receipt.Size > l.MaxReadBytes/2 {
		return nil, ErrLimit
	}
	c := comparisonRun{ctx: ctx, x: x, p: p, l: l, v: ComparisonEvidence{Source: x.state, Destination: id, Limitations: []string{
		"component comparison only; no production admission or whole-image preservation authority",
		"native observations and final rechecks are not an atomic filesystem snapshot; ADS namespace atomicity is unproved",
		"source WIM stores creation/access/write times; change time has no source value and is not applicable",
		"security offsets and zero layout/free-space padding are ignored; original raw descriptors and ordered complete ACE bodies are retained",
		"reparse data requires exact original bytes; no destination relocation is accepted or inferred",
	}}}
	if e = c.charge(128 << 10); e != nil {
		return nil, e
	}
	c.v.ReadBytes += x.state.Oracle.Receipt.Size
	if e = verifyOriginalMetadata(ctx, x.proof); e != nil {
		return nil, e
	}
	for _, q := range x.requirements {
		if e = c.unknown(q.Path, q.Field, q.Detail); e != nil {
			return nil, e
		}
		c.v.Unresolved[len(c.v.Unresolved)-1] = q
	}
	start, e := c.inventory()
	if e != nil {
		return nil, e
	}
	if start.Tree != id {
		return nil, ErrInput
	}
	c.v.InitialInventory = start
	if !start.Complete {
		if e = c.unknown(".", "inventory.complete", "native inventory is incomplete"); e != nil {
			return nil, e
		}
	}
	byPath := make(map[string]platform.InventoryEntry, len(start.Entries))
	for _, en := range start.Entries {
		if _, ok := byPath[en.Path]; ok {
			if e = c.mismatch(en.Path, "path", "one exact name", "duplicate", nil, nil); e != nil {
				return nil, e
			}
		}
		byPath[en.Path] = en
		if en.Status != "known" {
			if e = c.unknown(en.Path, "inventory."+en.Status, "actual native name is not an independently checked held entry"); e != nil {
				return nil, e
			}
		}
	}
	if e = c.charge(uint64(len(x.entries)) * 1024); e != nil {
		return nil, e
	}
	observations := make(map[string]platform.MetadataObservation, len(x.entries))
	type nativeKey struct {
		Volume uint64
		ID     [16]byte
	}
	groups := map[uint64]nativeKey{}
	nativeGroups := map[nativeKey]uint64{}
	for n, en := range x.entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		path := en.Original.Path
		name := strings.TrimPrefix(path, "/")
		if name == "" {
			name = "."
		}
		if len(path) > l.MaxStringBytes {
			return nil, ErrLimit
		}
		actual, ok := byPath[name]
		if !ok {
			if e = c.mismatch(path, "path", "present", "missing", nil, nil); e != nil {
				return nil, e
			}
			continue
		}
		delete(byPath, name)
		if actual.Status != "known" {
			continue
		}
		o, e := c.observe(name)
		if e != nil {
			return nil, e
		}
		observations[name] = o
		c.v.EntriesObserved++
		if o.Identity != actual.Identity {
			if e = c.mismatch(path, "identity", "inventory held identity", "changed held identity", nil, nil); e != nil {
				return nil, e
			}
		}
		for _, f := range []struct {
			name  string
			value platform.MetadataField
		}{{"basic", o.Basic}, {"file-id", o.FileID}, {"security", o.Security}, {"sacl", o.SACL}, {"streams", o.Streams}, {"ea", o.EAs}} {
			if f.value.Status != "complete" {
				if e = c.unknown(path, "native."+f.name, f.value.Status+": "+f.value.Detail); e != nil {
					return nil, e
				}
			}
		}
		if !o.Complete {
			if e = c.unknown(path, "native.complete", "aggregate observation is incomplete"); e != nil {
				return nil, e
			}
		}
		if o.FileID.Status == "complete" && (o.Identity.FileIndex == 0 || o.FileID128 == [16]byte{}) {
			if e = c.unknown(path, "native.file-id", "native held/file-ID identity is missing or zero"); e != nil {
				return nil, e
			}
		}
		if o.Basic.Status == "complete" {
			for _, v := range []struct {
				field     string
				want, got uint64
			}{{"attributes", uint64(en.Original.Attributes), uint64(o.Attributes)}, {"time.creation", en.Original.CreationTime, o.CreationTime}, {"time.access", en.Original.AccessTime, o.AccessTime}, {"time.write", en.Original.WriteTime, o.WriteTime}} {
				if v.want != v.got {
					if e = c.mismatch(path, v.field, fmt.Sprint(v.want), fmt.Sprint(v.got), nil, nil); e != nil {
						return nil, e
					}
				}
			}
		}
		if en.Original.Attributes&16 == 0 && o.FileID.Status == "complete" {
			if o.LinkCount != en.ExpectedLinks {
				if e = c.mismatch(path, "hardlinks.count", fmt.Sprint(en.ExpectedLinks), fmt.Sprint(o.LinkCount), nil, nil); e != nil {
					return nil, e
				}
			}
			key := nativeKey{o.VolumeSerial, o.FileID128}
			group := en.Original.HardlinkID
			if group == 0 {
				group = uint64(n) | 1<<63
			}
			if prior, ok := groups[group]; ok && prior != key {
				var expectedID, observedID [24]byte
				binary.LittleEndian.PutUint64(expectedID[:], prior.Volume)
				copy(expectedID[8:], prior.ID[:])
				binary.LittleEndian.PutUint64(observedID[:], key.Volume)
				copy(observedID[8:], key.ID[:])
				if e = c.mismatch(path, "hardlinks.equivalence", "same native identity", "distinct native identities", expectedID[:], observedID[:]); e != nil {
					return nil, e
				}
			}
			if prior, ok := nativeGroups[key]; ok && prior != group {
				var expectedGroups [16]byte
				var observedID [24]byte
				binary.LittleEndian.PutUint64(expectedGroups[:], prior)
				binary.LittleEndian.PutUint64(expectedGroups[8:], group)
				binary.LittleEndian.PutUint64(observedID[:], key.Volume)
				copy(observedID[8:], key.ID[:])
				if e = c.mismatch(path, "hardlinks.equivalence", "distinct source identities", "same native identity", expectedGroups[:], observedID[:]); e != nil {
					return nil, e
				}
			}
			groups[group] = key
			nativeGroups[key] = group
		}
		if en.Original.SecurityID != 0xffffffff && int(en.Original.SecurityID) < len(x.security) {
			if e = c.security(path, x.security[en.Original.SecurityID], o); e != nil {
				return nil, e
			}
		}
		if e = c.eas(path, en, o); e != nil {
			return nil, e
		}
		if e = c.reparse(path, en, o); e != nil {
			return nil, e
		}
		if o.Streams.Status == "complete" {
			if e = c.streams(path, name, en, o); e != nil {
				return nil, e
			}
		}
	}
	for path := range byPath {
		if e = c.mismatch(path, "path", "absent", "extra", nil, nil); e != nil {
			return nil, e
		}
	}
	// Recheck every previously observed entry after all content reads, then the
	// complete independent namespace again. The held owner/root is also checked.
	c.nativeStreams = 0 // The final observation pass has its own same count cap.
	for name, before := range observations {
		after, e := c.observe(name)
		if e != nil {
			return nil, e
		}
		if !reflect.DeepEqual(before, after) {
			if e = c.mismatch(name, "observation.drift", "initial held observation", "changed final observation", before.Basic.Raw, after.Basic.Raw); e != nil {
				return nil, e
			}
		}
	}
	end, e := c.inventory()
	if e != nil {
		return nil, e
	}
	c.v.FinalInventory = end
	if !reflect.DeepEqual(start, end) {
		if e = c.mismatch(".", "inventory.drift", "initial actual inventory", "changed final inventory", nil, nil); e != nil {
			return nil, e
		}
	}
	if x.state.Oracle.Receipt.Size > l.MaxReadBytes-c.v.ReadBytes {
		return nil, ErrLimit
	}
	c.v.ReadBytes += x.state.Oracle.Receipt.Size
	if e = verifyOriginalMetadata(ctx, x.proof); e != nil {
		return nil, e
	}
	if e = x.CheckLive(); e != nil {
		return nil, e
	}
	if e = p.CheckObservationLive(ctx); e != nil {
		return nil, e
	}
	if p.Identity() != id {
		return nil, ErrInput
	}
	c.v.Complete = x.state.ComparableComplete && len(c.v.Mismatches) == 0 && len(c.v.Unresolved) == 0
	return &PreservationComparison{expected: x, port: p, state: c.v, limits: l}, nil
}

func (c *comparisonRun) security(path string, want wimmeta.Security, o platform.MetadataObservation) error {
	if len(want.Raw) < 20 {
		return c.unknown(path, "source.security", "source descriptor has no complete comparable framing")
	}
	if o.Security.Status != "complete" || o.SACL.Status != "complete" {
		return nil
	}
	parse := func(raw []byte, field string) (wimmeta.Security, bool, error) {
		allow := c.l.MaxResultBytes - c.v.AccountedBytes
		if allow == 0 {
			return wimmeta.Security{}, false, ErrLimit
		}
		s, gaps, cost, e := wimmeta.InspectSecurity(c.ctx, raw, allow)
		if errors.Is(e, wimmeta.ErrLimit) {
			return s, false, ErrLimit
		}
		if e != nil {
			return s, false, c.unknown(path, "native."+field, "malformed self-relative security descriptor")
		}
		c.v.AccountedBytes += cost
		for _, g := range gaps {
			if g.Kind != "ace-semantics" {
				if e = c.unknown(path, "native."+field+"."+g.Kind, g.Detail); e != nil {
					return s, false, e
				}
			}
		}
		return s, true, nil
	}
	a, ok, e := parse(o.Security.Raw, "security")
	if e != nil || !ok {
		return e
	}
	b, ok, e := parse(o.SACL.Raw, "sacl")
	if e != nil || !ok {
		return e
	}
	const saclControl uint16 = 0x2a30
	wc := binary.LittleEndian.Uint16(want.Raw[2:])
	got := (binary.LittleEndian.Uint16(a.Raw[2:]) &^ saclControl) | (binary.LittleEndian.Uint16(b.Raw[2:]) & saclControl)
	if wc != got || want.Raw[0] != a.Raw[0] || want.Raw[1] != a.Raw[1] {
		if e = c.mismatch(path, "security.control", fmt.Sprint(wc), fmt.Sprint(got), want.Raw, a.Raw); e != nil {
			return e
		}
	}
	// Representation and resource-manager control are shared header fields,
	// not SACL-specific bits. Check them in both independently queried headers;
	// selecting SACL fields must not discard a conflicting shared control value.
	if binary.LittleEndian.Uint16(b.Raw[2:])&0xc000 != wc&0xc000 || b.Raw[1] != want.Raw[1] {
		if e = c.mismatch(path, "security.control", "source shared control/header", "different SACL query shared control/header", want.Raw, b.Raw); e != nil {
			return e
		}
	}
	for _, v := range []struct {
		field     string
		want, got []byte
	}{{"security.owner", want.Owner.Raw, a.Owner.Raw}, {"security.group", want.Group.Raw, a.Group.Raw}} {
		if !bytes.Equal(v.want, v.got) {
			if e = c.mismatch(path, v.field, "source SID", "different SID", v.want, v.got); e != nil {
				return e
			}
		}
	}
	for _, v := range []struct {
		field     string
		want, got *wimmeta.ACL
		raw       []byte
	}{{"security.dacl", want.DACL, a.DACL, a.Raw}, {"security.sacl", want.SACL, b.SACL, b.Raw}} {
		if !sameACL(want.Raw, v.want, v.raw, v.got) {
			if e = c.mismatch(path, v.field, "source ordered raw ACE bodies", "different ACL", want.Raw, v.raw); e != nil {
				return e
			}
		}
	}
	return nil
}
func sameACL(araw []byte, a *wimmeta.ACL, braw []byte, b *wimmeta.ACL) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Revision != b.Revision || len(a.ACEs) != len(b.ACEs) {
		return false
	}
	for n, x := range a.ACEs {
		y := b.ACEs[n]
		if !bytes.Equal(araw[x.Offset:uint64(x.Offset)+uint64(x.Size)], braw[y.Offset:uint64(y.Offset)+uint64(y.Size)]) {
			return false
		}
	}
	return true
}
func (c *comparisonRun) eas(path string, en EntryExpectation, o platform.MetadataObservation) error {
	if o.EAs.Status != "complete" {
		return nil
	}
	if e := c.charge(uint64(256 + (len(o.ExtendedAttributes)+len(en.EAs))*256)); e != nil {
		return e
	}
	seen := make(map[string]bool, len(o.ExtendedAttributes))
	expected := make(map[string]wimmeta.SourceEA, len(en.EAs))
	for _, ea := range en.EAs {
		if e := c.charge(uint64(len(ea.Name) * 2)); e != nil {
			return e
		}
		key := string(ea.Name)
		if _, ok := expected[key]; ok {
			if e := c.unknown(path, "ea.source", "duplicate source EA name"); e != nil {
				return e
			}
		}
		expected[key] = ea
	}
	for _, ea := range o.ExtendedAttributes {
		if e := c.charge(uint64(len(ea.Name) * 2)); e != nil {
			return e
		}
		key := string(ea.Name)
		if len(ea.Name) == 0 || len(ea.Name) > 255 || len(ea.Value) > 65535 || bytes.IndexByte(ea.Name, 0) >= 0 {
			if e := c.unknown(path, "native.ea", "malformed native EA name/value framing"); e != nil {
				return e
			}
			continue
		}
		if ea.Flags&^byte(0x80) != 0 {
			if e := c.unknown(path, "native.ea.flags", "unsupported native EA flags"); e != nil {
				return e
			}
		}
		want, ok := expected[key]
		if !ok || seen[key] || want.Flags != ea.Flags || !bytes.Equal(want.Value, ea.Value) {
			var wr []byte
			var e error
			if ok {
				wr, e = c.eaWitness(want.Name, want.Flags, want.Value)
				if e != nil {
					return e
				}
			}
			gr, e := c.eaWitness(ea.Name, ea.Flags, ea.Value)
			if e != nil {
				return e
			}
			if e := c.mismatch(path, "ea", "source EA name/flags/value", "different native EA", wr, gr); e != nil {
				return e
			}
		}
		seen[key] = true
		delete(expected, key)
	}
	for _, want := range expected {
		wr, e := c.eaWitness(want.Name, want.Flags, want.Value)
		if e != nil {
			return e
		}
		if e := c.mismatch(path, "ea", "recorded source EA", "missing", wr, nil); e != nil {
			return e
		}
	}
	return nil
}
func (c *comparisonRun) eaWitness(name []byte, flags byte, value []byte) ([]byte, error) {
	n := 5 + len(name) + len(value)
	if e := c.charge(uint64(n*2 + 32)); e != nil {
		return nil, e
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint16(b, uint16(len(value)))
	b[2] = byte(len(name))
	b[3] = flags
	copy(b[4:], name)
	copy(b[5+len(name):], value)
	return b, nil
}
func (c *comparisonRun) reparse(path string, en EntryExpectation, o platform.MetadataObservation) error {
	if en.Original.Attributes&0x400 == 0 {
		if o.Reparse.Status != "not-present" {
			return c.mismatch(path, "reparse", "not present", o.Reparse.Status, nil, o.Reparse.Raw)
		}
		return nil
	}
	if o.Reparse.Status != "complete" {
		return c.unknown(path, "native.reparse", o.Reparse.Status)
	}
	raw := o.Reparse.Raw
	if len(raw) < 8 {
		return c.unknown(path, "native.reparse", "malformed reparse header")
	}
	tag, size := binary.LittleEndian.Uint32(raw), int(binary.LittleEndian.Uint16(raw[4:]))
	header := 8
	if tag&0x80000000 == 0 {
		header = 24
	}
	if len(raw) < header || size+header != len(raw) {
		return c.unknown(path, "native.reparse", "unsupported or malformed native reparse framing; Microsoft GUID form requires a source-exact rule")
	}
	if tag != en.Original.ReparseTag || o.ReparseTag != tag {
		return c.mismatch(path, "reparse.tag", fmt.Sprint(en.Original.ReparseTag), fmt.Sprint(tag), nil, raw)
	}
	if binary.LittleEndian.Uint16(raw[6:]) != en.Original.ReparseReserved {
		return c.mismatch(path, "reparse.reserved", fmt.Sprint(en.Original.ReparseReserved), fmt.Sprint(binary.LittleEndian.Uint16(raw[6:])), nil, raw)
	}
	if !bytes.Equal(en.ReparseData, raw[8:]) {
		return c.mismatch(path, "reparse.data", "exact source blob; no relocation", "different native blob", en.ReparseData, raw[8:])
	}
	return nil
}
func (c *comparisonRun) streams(path, name string, en EntryExpectation, o platform.MetadataObservation) error {
	if e := c.charge(uint64(512 + len(o.NamedStreams)*256)); e != nil {
		return e
	}
	observed := map[string]platform.StreamObservation{}
	for _, s := range o.NamedStreams {
		if e := c.charge(uint64(128 + len(s.Name)*8)); e != nil {
			return e
		}
		key := string(utf16.Decode(s.Name))
		if !slices.Equal(utf16.Encode([]rune(key)), s.Name) {
			if e := c.unknown(path, "native.streams.name", "invalid native UTF-16 stream name"); e != nil {
				return e
			}
			continue
		}
		if _, ok := observed[key]; ok {
			if e := c.mismatch(path, "streams.names", "one stream name", "duplicate", nil, nil); e != nil {
				return e
			}
		}
		observed[key] = s
	}
	for j, s := range en.Original.Streams {
		if s.Kind == "directory-placeholder" || s.Kind == "unused-main" || s.Kind == "reparse" {
			continue
		}
		if s.Kind != "data" && s.Kind != "named-data" {
			if e := c.unknown(path, "stream.role", s.Kind); e != nil {
				return e
			}
			continue
		}
		if e := c.charge(uint64(128 + len(s.Name)*8)); e != nil {
			return e
		}
		stream := string(utf16.Decode(s.Name))
		key := ":" + stream + ":$DATA"
		got, ok := observed[key]
		if !ok {
			if e := c.mismatch(path, "streams.names", key, "missing", nil, nil); e != nil {
				return e
			}
			continue
		}
		delete(observed, key)
		field := fmt.Sprintf("stream[%d].content", j)
		if !s.SizeKnown {
			if e := c.unknown(path, field, "source length is unresolved"); e != nil {
				return e
			}
			continue
		}
		if got.Size != s.Size {
			if e := c.mismatch(path, field, fmt.Sprint(s.Size), fmt.Sprint(got.Size), nil, nil); e != nil {
				return e
			}
			continue
		}
		if strings.Contains(stream, ":") {
			if e := c.unknown(path, field, "source stream name cannot use the held reader"); e != nil {
				return e
			}
			continue
		}
		if s.Size > c.l.MaxReadBytes-c.v.ReadBytes {
			return ErrLimit
		}
		c.v.ReadBytes += s.Size
		h1, h256 := sha1.New(), sha256.New()
		var b [64 << 10]byte
		completeRead := true
		for off := uint64(0); off < s.Size; {
			if e := c.ctx.Err(); e != nil {
				return e
			}
			n := min(uint64(len(b)), s.Size-off)
			got, readErr := c.p.ReadOwnedAt(c.ctx, name, stream, b[:n], int64(off))
			if readErr != nil && !(errors.Is(readErr, io.EOF) && uint64(got) == n) || uint64(got) != n {
				if e := c.unknown(path, field, "held stream content read failed or was incomplete"); e != nil {
					return e
				}
				completeRead = false
				break
			}
			h1.Write(b[:n])
			h256.Write(b[:n])
			off += n
		}
		want := en.Content[j]
		g1, g256 := hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h256.Sum(nil))
		if (s.Size > 0 && g1 != want.SHA1) || g256 != want.SHA256 {
			if e := c.mismatch(path, field, want.SHA256, g256, nil, nil); e != nil {
				return e
			}
		}
		if completeRead {
			c.v.StreamsCompared++
		}
	}
	if en.Original.Attributes&16 != 0 {
		if d, ok := observed["::$DATA"]; ok && d.Size == 0 {
			delete(observed, "::$DATA")
		}
	}
	for key := range observed {
		if e := c.mismatch(path, "streams.names", "absent", key, nil, nil); e != nil {
			return e
		}
	}
	return nil
}
