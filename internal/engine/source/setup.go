package source

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

var ErrSetupShape = errors.New("unsupported source-bound Setup archive transformation")

const originalLaunch = "[LaunchApp]\r\nAppPath=X:\\sources\\recovery\\recenv.exe\r\n"
const setupLaunch = "[LaunchApp]\r\nAppPath=X:\\sources\\setup.exe\r\n"
const launchPath = "/windows/system32/winpeshl.ini"
const setupRule = "canonical-pe-19041-x86/setup-v1: exact recovery LaunchApp to X:\\sources\\setup.exe CRLF; graft source-media root setup.exe and sources/** except reserved generated images; merge directories retaining PE records; refuse existing files; retain all other raw PE dentries/streams/tags and security IDs/descriptors; append exact media security descriptors with ID mapping; relocate ChildOffset only with ASCII uppercase sibling collation and retain explicit empty lists; one raw standard boot image INDEX=1 BootIndex=1; validate original and recompute four IMAGE summary scalars using per-name logical streams/extra hardlink names, exclude root directory; all other original XML body and labels unchanged"

type SetupBootDescriptor struct {
	Source                                                                                       model.SourceIdentity
	ManifestDigest, RuleDigest, ProofDigest, OriginalXMLSHA256, OutputXMLSHA256                  string
	Index                                                                                        wimindex.ContentClaim
	Metadata                                                                                     wimindex.MetadataReceipt
	Oracle                                                                                       wimmeta.Claim
	ReferenceDigest                                                                              string
	Media                                                                                        MediaTreeDescriptor
	ResourceDigest, MetadataSHA1, MetadataSHA256, LaunchSHA1, LaunchSHA256                       string
	Resources, OriginalRecords, GraftFiles, GraftDirectories, OriginalSecurity, ImportedSecurity int
	MetadataBytes, ResourceBytes, AccountedBytes, XMLBytes                                       uint64
	OriginalSummary, OutputSummary                                                               ImageSummary
}
type setupNode struct {
	entry       wimmeta.Entry
	raw         []byte
	graft       bool
	children    []int
	listPresent bool
	marker      uint64
	offset      uint64
}
type setupResource struct {
	identity ResourceIdentity
	reader   io.ReaderAt
}
type BoundSetupBoot struct {
	state      SetupBootDescriptor
	input      Inputs
	media      *BoundMediaTree
	nodes      []setupNode
	paths      map[string]int
	security   [][]byte
	rootMarker uint64
	raw, xml   []byte
	resources  []setupResource
	limits     Limits
}

func (r *BoundSetupBoot) Descriptor() SetupBootDescriptor {
	if r == nil {
		return SetupBootDescriptor{}
	}
	d := r.state
	d.Media.ReservedPaths = slices.Clone(d.Media.ReservedPaths)
	return d
}
func (r *BoundSetupBoot) XML() []byte         { return slices.Clone(r.xml) }
func (r *BoundSetupBoot) HeaderFlags() uint32 { return r.state.Metadata.Header.Flags & 0x80 }
func (r *BoundSetupBoot) CheckLive() error {
	if r == nil || r.input.Metadata == nil || r.input.Oracle == nil || r.input.References == nil || r.media == nil || r.input.Oracle.Claim() != r.state.Oracle {
		return ErrInput
	}
	if _, e := r.input.Metadata.ReadAt(nil, 0); e != nil {
		return e
	}
	if e := r.input.References.CheckLive(); e != nil {
		return e
	}
	return r.media.CheckLive()
}

type setupBorrower struct {
	owner  *BoundSetupBoot
	reader io.ReaderAt
}

func (a setupBorrower) ReadAt(b []byte, off int64) (int, error) {
	if e := a.owner.CheckLive(); e != nil {
		return 0, e
	}
	return a.reader.ReadAt(b, off)
}
func (r *BoundSetupBoot) Resource(n int) (ResourceIdentity, io.ReaderAt, error) {
	if e := r.CheckLive(); e != nil {
		return ResourceIdentity{}, nil, e
	}
	if n < 0 || n >= len(r.resources) {
		return ResourceIdentity{}, nil, ErrInput
	}
	v := r.resources[n]
	return v.identity, setupBorrower{r, v.reader}, nil
}

func setupKey(p string) (string, error) {
	if p == "/" {
		return p, nil
	}
	v, e := MediaPathKey(strings.TrimPrefix(p, "/"))
	if e != nil {
		return "", ErrSetupShape
	}
	return "/" + v, nil
}
func rawMetadata(ctx context.Context, a *wimindex.MetadataArtifact) ([]byte, error) {
	r := a.Receipt()
	b := make([]byte, int(r.Size))
	for off := 0; off < len(b); {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		n := min(64<<10, len(b)-off)
		got, e := a.ReadAt(b[off:off+n], int64(off))
		if e != nil || got != n {
			return nil, errors.Join(ErrIntegrity, e)
		}
		off += n
	}
	h := sha1.Sum(b)
	if bytesDigest(b) != r.SHA256 || hex.EncodeToString(h[:]) != r.SHA1 {
		return nil, ErrIntegrity
	}
	return b, nil
}

// BindSetupBoot borrows complete live content closure, preserving the original
// Oracle's opaque semantic gaps. The fixed rule is data transformation authority
// only. No caller path, patch, command string, toolchain or readiness is accepted.
func BindSetupBoot(ctx context.Context, in Inputs, media *BoundMediaTree, limits Limits) (*BoundSetupBoot, error) {
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
	if in.Index == nil || in.Metadata == nil || in.Oracle == nil || in.References == nil || media == nil {
		return nil, ErrInput
	}
	if e = media.CheckLive(); e != nil {
		return nil, e
	}
	index, oracle, view := in.Index.ContentClaim(), in.Oracle.Claim(), in.References.Claim()
	receipt := in.Metadata.Receipt()
	md := media.Descriptor()
	if len(md.ReservedPaths) != 2 {
		return nil, ErrSetupShape
	}
	reserved := map[string]bool{}
	for _, p := range md.ReservedPaths {
		key, e := MediaPathKey(p)
		if e != nil || reserved[key] || key != "sources/boot.wim" && key != "sources/install.wim" {
			return nil, ErrSetupShape
		}
		reserved[key] = true
	}
	if !index.Verified || !oracle.Verified || !view.Verified || !view.ReferenceClosure || view.References != oracle.References || view.Oracle != oracle || oracle.Receipt != receipt || !in.Index.MatchesMetadataReceipt(receipt) || index.Source != in.Manifest.Source || index.ManifestDigest != in.Manifest.Digest || md.Source != index.Source || md.ManifestDigest != index.ManifestDigest || md.Index != index || md.Metadata.Payload != receipt.Payload || md.Metadata.Entry.ImageIndex == receipt.Entry.ImageIndex {
		return nil, ErrInput
	}
	if view.References > l.MaxReferences || oracle.Summary.Entries+md.Entries+1 > l.MaxEntries {
		return nil, ErrLimit
	}
	if receipt.Header.XML.Size > uint64(l.MaxXMLBytes) {
		return nil, ErrLimit
	}
	accounted := oracle.Summary.AccountedBytes + md.AccountedBytes + receipt.Size*6 + md.Metadata.Size*6 + uint64(oracle.Summary.Entries+md.Entries+1)*4096 + uint64(view.References+md.Resources+2)*4096 + receipt.Header.XML.Size*16 + 4096
	if accounted > l.MaxResultBytes || receipt.Size > 64<<20 || receipt.Size*8+md.Metadata.Size*8+uint64(receipt.Payload.Size)*2+receipt.Header.XML.Size+uint64(md.Files)*128+4096 > l.MaxReadBytes {
		return nil, ErrLimit
	}
	resources, e := bindReferences(ctx, in, view, l, &accounted)
	if e != nil {
		return nil, e
	}
	xml, original, inv, e := selectedXML(ctx, in, receipt, l)
	if e != nil {
		return nil, e
	}
	im := inv.Images[0]
	if im.Architecture != "x86" || in.Manifest.Source.Architecture != "x86" || in.Manifest.Source.Language != "en-us" || im.Edition != "WindowsPE" || im.InstallationType != "WindowsPE" || im.Build != "10.0.19041.1" || original != md.OriginalXMLSHA256 {
		return nil, ErrSetupShape
	}
	r := &BoundSetupBoot{input: in, media: media, paths: map[string]int{}, limits: l, xml: xml, state: SetupBootDescriptor{Source: in.Manifest.Source, ManifestDigest: in.Manifest.Digest, RuleDigest: bytesDigest([]byte(setupRule)), OriginalXMLSHA256: original, OutputXMLSHA256: bytesDigest(xml), Index: index, Metadata: receipt, Oracle: oracle, ReferenceDigest: view.Digest, Media: md, AccountedBytes: accounted, XMLBytes: uint64(len(xml))}}
	peRaw, e := rawMetadata(ctx, in.Metadata)
	if e != nil {
		return nil, e
	}
	mediaRaw, e := rawMetadata(ctx, media.metadata)
	if e != nil {
		return nil, e
	}
	ps, ms := in.Oracle.Snapshot(), media.oracle.Snapshot()
	if e = r.planRecords(ps, ms, peRaw, mediaRaw); e != nil {
		return nil, fmt.Errorf("Setup record planning: %w", e)
	}
	if e = r.bindSetupContent(ctx, resources); e != nil {
		return nil, fmt.Errorf("Setup content binding: %w", e)
	}
	if e = r.rewriteSummaryXML(resources); e != nil {
		return nil, e
	}
	if e = r.writeMetadata(ctx); e != nil {
		return nil, e
	}
	r.state.MetadataBytes = uint64(len(r.raw))
	h := sha1.Sum(r.raw)
	r.state.MetadataSHA1 = hex.EncodeToString(h[:])
	r.state.MetadataSHA256 = bytesDigest(r.raw)
	r.resources[0] = setupResource{ResourceIdentity{r.state.MetadataSHA1, r.state.MetadataSHA256, digest(struct{ Rule, PE, Media string }{r.state.RuleDigest, receipt.SHA256, md.Metadata.SHA256}), uint64(len(r.raw)), 1}, bytes.NewReader(r.raw)}
	ids := make([]ResourceIdentity, len(r.resources))
	for i, v := range r.resources {
		ids[i] = v.identity
		r.state.ResourceBytes += v.identity.Size
	}
	r.state.Resources = len(ids)
	r.state.ResourceDigest = digest(ids)
	r.state.ProofDigest = digest(r.state)
	if e = r.InspectMetadata(ctx, bytes.NewReader(r.raw), uint64(len(r.raw))); e != nil {
		return nil, e
	}
	if e = verifyMetadata(ctx, in.Metadata, receipt); e != nil {
		return nil, e
	}
	if e = verifyMetadata(ctx, media.metadata, md.Metadata); e != nil {
		return nil, e
	}
	if e = r.CheckLive(); e != nil {
		return nil, e
	}
	return r, nil
}

func (r *BoundSetupBoot) bindSetupContent(ctx context.Context, base []boundResource) error {
	launch := r.nodes[r.paths[launchPath]].entry
	if launch.Attributes&0x4410 != 0 || launch.HardlinkID != 0 || len(launch.Streams) != 1 || launch.Streams[0].Kind != "data" || launch.Streams[0].Reference < 0 {
		return ErrSetupShape
	}
	s := launch.Streams[0]
	if s.Reference+1 >= len(base) {
		return ErrInput
	}
	id := base[s.Reference+1].identity
	if id.Size != uint64(len(originalLaunch)) {
		return ErrSetupShape
	}
	a, e := r.input.References.Content(s.Reference, 0)
	if e != nil {
		return e
	}
	b := make([]byte, len(originalLaunch))
	if n, e := a.ReadAt(b, 0); e != nil || n != len(b) || string(b) != originalLaunch || bytesDigest(b) != id.SHA256 {
		return errors.Join(ErrSetupShape, e)
	}
	// A shared content hash is safe: only this dentry changes. A shared inode
	// was refused above because changing one hardlink would corrupt its meaning.
	available := map[string]setupResource{}
	for i, v := range base {
		if i == 0 {
			continue
		}
		a, e := r.input.References.Content(v.reference, 0)
		if e != nil {
			return e
		}
		available[v.identity.SHA1] = setupResource{v.identity, a}
	}
	for i := 1; i < len(r.media.resources); i++ {
		id, a, e := r.media.Resource(i)
		if e != nil {
			return e
		}
		if old, ok := available[id.SHA1]; ok {
			if old.identity.SHA256 != id.SHA256 || old.identity.Size != id.Size {
				return ErrIntegrity
			}
			id.ProvenanceDigest = digest([]string{old.identity.ProvenanceDigest, id.ProvenanceDigest})
		}
		available[id.SHA1] = setupResource{id, a}
	}
	h := sha1.Sum([]byte(setupLaunch))
	hash := hex.EncodeToString(h[:])
	r.state.LaunchSHA1 = hash
	r.state.LaunchSHA256 = bytesDigest([]byte(setupLaunch))
	if _, ok := available[hash]; ok {
		return ErrSetupShape
	}
	available[hash] = setupResource{ResourceIdentity{hash, r.state.LaunchSHA256, r.state.RuleDigest, uint64(len(setupLaunch)), 0}, bytes.NewReader([]byte(setupLaunch))}
	for _, path := range []string{"/setup.exe", "/sources/setup.exe"} {
		i, ok := r.paths[path]
		if !ok || !r.nodes[i].graft {
			return ErrSetupShape
		}
		en := r.nodes[i].entry
		if en.Attributes&0x4410 != 0 || len(en.Streams) != 1 || en.Streams[0].Kind != "data" {
			return ErrSetupShape
		}
		v, ok := available[en.Streams[0].SHA1]
		if !ok {
			return ErrInput
		}
		if e = inspectX86Image(ctx, v.reader, v.identity.Size, true); e != nil {
			return fmt.Errorf("%s: %w", path, e)
		}
	}
	// Every grafted PE binary, including DLLs and language resources, must match
	// the declared target. Complete source identity alone cannot excuse a foreign
	// architecture within the imported tree. All bytes stay data; none execute.
	for _, n := range r.nodes {
		if !n.graft || n.entry.Attributes&16 != 0 {
			continue
		}
		v, ok := available[n.entry.Streams[0].SHA1]
		if !ok {
			if n.entry.Streams[0].SHA1 == "0000000000000000000000000000000000000000" {
				continue
			}
			return ErrInput
		}
		binaryPath := false
		for _, ext := range []string{".exe", ".dll", ".sys", ".mui"} {
			binaryPath = binaryPath || strings.HasSuffix(strings.ToLower(n.entry.Path), ext)
		}
		var magic [2]byte
		if v.identity.Size >= 2 {
			if got, e := v.reader.ReadAt(magic[:], 0); e != nil || got != 2 {
				return ErrIntegrity
			}
		}
		if binaryPath || string(magic[:]) == "MZ" {
			if e := inspectX86Image(ctx, v.reader, v.identity.Size, false); e != nil {
				return fmt.Errorf("%s: %w", n.entry.Path, e)
			}
		}
	}
	r.resources = []setupResource{{}}
	selected := map[string]int{}
	for i, n := range r.nodes {
		for _, s := range n.entry.Streams {
			key := s.SHA1
			if n.entry.Path != "/" && i == r.paths[launchPath] {
				key = hash
			}
			if key == "0000000000000000000000000000000000000000" {
				continue
			}
			v, ok := available[key]
			if !ok {
				return ErrInput
			}
			at, ok := selected[key]
			if !ok {
				at = len(r.resources)
				v.identity.References = 0
				r.resources = append(r.resources, v)
				selected[key] = at
			}
			if r.resources[at].identity.References == ^uint32(0) {
				return ErrLimit
			}
			r.resources[at].identity.References++
		}
	}
	return ctx.Err()
}
func inspectX86Image(ctx context.Context, r io.ReaderAt, size uint64, application bool) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if size < 88 || size > 16<<20 {
		return ErrSetupShape
	}
	var dos [64]byte
	if n, e := r.ReadAt(dos[:], 0); e != nil || n != 64 {
		return ErrIntegrity
	}
	off := uint64(binary.LittleEndian.Uint32(dos[60:]))
	if string(dos[:2]) != "MZ" || off < 64 || off > size-24 {
		return ErrSetupShape
	}
	var nt [24]byte
	if n, e := r.ReadAt(nt[:], int64(off)); e != nil || n != 24 {
		return ErrIntegrity
	}
	le := binary.LittleEndian
	if string(nt[:4]) != "PE\x00\x00" || le.Uint16(nt[4:]) != 0x14c || le.Uint16(nt[22:])&2 != 2 || application && le.Uint16(nt[22:])&0x2000 != 0 || le.Uint16(nt[6:]) > 96 || le.Uint16(nt[20:]) > 4096 {
		return ErrSetupShape
	}
	return ctx.Err()
}
