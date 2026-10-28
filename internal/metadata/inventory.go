// Package metadata makes read-only observations about verified source material.
// An Inventory never authorizes image mutation or establishes buildability.
package metadata

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf16"

	"uupbuilder/internal/model"
)

var (
	ErrInvalidInput        = errors.New("invalid metadata inspection input")
	ErrIntegrity           = errors.New("metadata integrity check failed")
	ErrLimit               = errors.New("metadata inspection limit exceeded")
	ErrMalformedMetadata   = errors.New("malformed metadata")
	ErrConflictingMetadata = errors.New("conflicting metadata")
	ErrInvalidEvidence     = errors.New("invalid metadata evidence")
)

type Format string

const (
	FormatCompositionXML  Format = "composition-xml"
	FormatCBSXML          Format = "cbs-xml"
	FormatWIMXML          Format = "wim-xml"
	FormatAppxXML         Format = "appx-xml"
	FormatStoreLicenseXML Format = "store-license-xml"
)

// Limits bound both raw metadata and its decoded representation. MaxXMLTokens
// also caps the aggregate number of provider assertions. Zero selects
// conservative defaults. Callers may lower, but cannot raise, the hard ceilings.
type Limits struct {
	MaxDocumentBytes int64
	MaxTotalBytes    int64
	MaxDocuments     int
	MaxXMLDepth      int
	MaxXMLTokens     int
}

// LocalResource borrows an immutable materialized file. Inspect validates its
// complete digest and size against the frozen manifest before parsing it or
// passing it to a provider. The caller retains ownership/lifetime of the path.
type LocalResource struct {
	Identity model.PayloadIdentity
	Path     string
}
type MetadataFile struct {
	Resource LocalResource
	Format   Format
	Gzip     bool
}
type ResourceReference struct {
	Payload model.PayloadIdentity
	Member  string
}
type DocumentReference struct {
	Resource ResourceReference
	SHA256   string
}

// Document retains the exact input bytes, including compression/BOM, separately
// from observations. SHA256 addresses those original bytes, not reserialized XML.
type Document struct {
	Reference  DocumentReference
	Format     Format
	Original   []byte
	Gzip       bool
	Provenance string
}

// MetadataDocument is raw metadata returned by a trusted read-only inspector.
// Resource.Payload must be the inspected container; Member is a lexical relative
// member name. Provenance must identify the inspection method/provider version.
type MetadataDocument struct {
	Resource   ResourceReference
	Format     Format
	Original   []byte
	Gzip       bool
	Provenance string
}

// ReadOnlyProvider inspects the supplied verified resource without modifying it
// or launching mutation operations. It must honor context and limits while
// reading/decompressing; Inspect independently bounds every returned document.
// This package supplies no executable/helper adapter. A future proven adapter
// may enumerate archive metadata or inspect WIM XML/content through this port.
type ReadOnlyProvider interface {
	Inspect(context.Context, LocalResource, Limits) (ProviderResult, error)
}
type Inspection struct {
	Resource LocalResource
	Provider ReadOnlyProvider
}
type ProviderResult struct {
	Documents       []MetadataDocument
	Roles           []RoleEvidence
	Absences        []AbsenceEvidence
	Layouts         []LayoutEvidence
	Licenses        []LicenseEvidence
	AppPhases       []AppPhaseEvidence
	EditionBases    []EditionBase
	PayloadBindings []PayloadBinding
}

// Evidence is a trusted provider's semantic assertion, bound to the exact source
// revision and retained original document bytes. Selector identifies the field,
// record or inspected content supporting the assertion. Inspect validates the
// bindings, not the provider's semantic implementation. A caller's completeness
// boolean, an unexamined file list, a filename or an index alone is never proof
// that required upstream material is absent.
type Evidence struct {
	Source   model.SourceIdentity
	Document DocumentReference
	Selector string
}
type InspectRequest struct {
	Source      model.SourceIdentity
	Manifest    model.PayloadManifest
	Files       []MetadataFile
	Inspections []Inspection
	Limits      Limits
}
type Inventory struct {
	Source         model.SourceIdentity
	Manifest       model.PayloadManifest
	Documents      []Document
	Roles          []RoleEvidence
	Images         []Image
	Packages       []Package
	Compositions   []Composition
	Apps           AppInventory
	EditionBases   []EditionBase
	Layouts        []LayoutEvidence
	Absences       []AbsenceEvidence
	Gaps           []Gap
	Classification Classification
}
type Gap struct {
	Code, Detail string
	Document     *DocumentReference
}

// Inspect verifies bytes and returns a static inventory with explicit gaps.
// On error the returned partial inventory is diagnostic data, not a completed
// inspection. No file is created, changed, mounted, extracted or executed.
func Inspect(ctx context.Context, req InspectRequest) (Inventory, error) {
	if ctx == nil {
		return Inventory{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	if req.Source.Validate() != nil || req.Manifest.Validate() != nil || req.Source != req.Manifest.Source {
		return Inventory{}, ErrInvalidInput
	}
	limits, err := inspectionLimits(req.Limits)
	if err != nil {
		return Inventory{}, err
	}
	inv := Inventory{Source: req.Source, Manifest: req.Manifest}
	inv.Manifest.Payloads = slices.Clone(req.Manifest.Payloads)
	inv.Manifest.Queries = slices.Clone(req.Manifest.Queries)
	known := make(map[model.PayloadIdentity]bool)
	for _, payload := range req.Manifest.Payloads {
		known[payload.Identity] = true
	}
	var results []ProviderResult
	var total int64
	var facts int
	addDocument := func(raw MetadataDocument) error {
		if !known[raw.Resource.Payload] || !validMember(raw.Resource.Member) || raw.Provenance == "" {
			return ErrInvalidEvidence
		}
		if int64(len(raw.Original)) > limits.MaxDocumentBytes || int64(len(raw.Original)) > limits.MaxTotalBytes-total || len(inv.Documents) >= limits.MaxDocuments {
			return ErrLimit
		}
		sum := sha256.Sum256(raw.Original)
		ref := DocumentReference{Resource: raw.Resource, SHA256: hex.EncodeToString(sum[:])}
		for _, old := range inv.Documents {
			if old.Reference.Resource == ref.Resource {
				if old.Reference != ref || old.Format != raw.Format || old.Gzip != raw.Gzip {
					return ErrConflictingMetadata
				}
				return nil
			}
		}
		decoded := raw.Original
		if supportedFormat(raw.Format) {
			var err error
			decoded, err = decodeMetadata(ctx, raw.Original, raw.Gzip, limits.MaxDocumentBytes)
			if err != nil {
				return err
			}
		}
		// Account both compressed and expanded bytes so many individually small
		// documents cannot evade the aggregate expansion budget.
		cost := max(int64(len(raw.Original)), int64(len(decoded)))
		if cost > limits.MaxTotalBytes-total {
			return ErrLimit
		}
		total += cost
		doc := Document{Reference: ref, Format: raw.Format, Original: slices.Clone(raw.Original), Gzip: raw.Gzip, Provenance: raw.Provenance}
		inv.Documents = append(inv.Documents, doc)
		return inv.parseDocument(ctx, doc, decoded, limits, known)
	}
	for _, input := range req.Files {
		if !known[input.Resource.Identity] {
			return inv, ErrInvalidInput
		}
		data, err := readResource(ctx, input.Resource, limits.MaxDocumentBytes, true)
		if err != nil {
			return inv, err
		}
		if err := addDocument(MetadataDocument{Resource: ResourceReference{Payload: input.Resource.Identity}, Format: input.Format, Original: data, Gzip: input.Gzip, Provenance: input.Resource.Identity.Provenance.Source}); err != nil {
			return inv, err
		}
	}
	for _, inspection := range req.Inspections {
		if inspection.Provider == nil || !known[inspection.Resource.Identity] {
			return inv, ErrInvalidInput
		}
		if _, err := readResource(ctx, inspection.Resource, 0, false); err != nil {
			return inv, err
		}
		result, err := inspection.Provider.Inspect(ctx, inspection.Resource, limits)
		if err != nil {
			return inv, err
		}
		if err := ctx.Err(); err != nil {
			return inv, err
		}
		for _, count := range []int{len(result.Roles), len(result.Absences), len(result.Layouts), len(result.Licenses), len(result.AppPhases), len(result.EditionBases), len(result.PayloadBindings)} {
			if count > limits.MaxXMLTokens-facts {
				return inv, ErrLimit
			}
			facts += count
		}
		for _, doc := range result.Documents {
			if doc.Resource.Payload != inspection.Resource.Identity {
				return inv, ErrInvalidEvidence
			}
			if err := addDocument(doc); err != nil {
				return inv, err
			}
		}
		results = append(results, result)
	}
	for _, result := range results {
		if err := inv.applyEvidence(result, known); err != nil {
			return inv, err
		}
	}
	if err := inv.finish(); err != nil {
		return inv, err
	}
	return inv, ctx.Err()
}

func inspectionLimits(requested Limits) (Limits, error) {
	ceilings := Limits{MaxDocumentBytes: 8 << 20, MaxTotalBytes: 32 << 20, MaxDocuments: 256, MaxXMLDepth: 64, MaxXMLTokens: 100000}
	if requested.MaxDocumentBytes < 0 || requested.MaxTotalBytes < 0 || requested.MaxDocuments < 0 || requested.MaxXMLDepth < 0 || requested.MaxXMLTokens < 0 {
		return Limits{}, ErrInvalidInput
	}
	if requested.MaxDocumentBytes > ceilings.MaxDocumentBytes || requested.MaxTotalBytes > ceilings.MaxTotalBytes || requested.MaxDocuments > ceilings.MaxDocuments || requested.MaxXMLDepth > ceilings.MaxXMLDepth || requested.MaxXMLTokens > ceilings.MaxXMLTokens {
		return Limits{}, ErrLimit
	}
	if requested.MaxDocumentBytes == 0 {
		requested.MaxDocumentBytes = ceilings.MaxDocumentBytes
	}
	if requested.MaxTotalBytes == 0 {
		requested.MaxTotalBytes = ceilings.MaxTotalBytes
	}
	if requested.MaxDocuments == 0 {
		requested.MaxDocuments = ceilings.MaxDocuments
	}
	if requested.MaxXMLDepth == 0 {
		requested.MaxXMLDepth = ceilings.MaxXMLDepth
	}
	if requested.MaxXMLTokens == 0 {
		requested.MaxXMLTokens = ceilings.MaxXMLTokens
	}
	return requested, nil
}

func validMember(member string) bool {
	if member == "" {
		return true
	}
	normalized, err := model.ValidateRelativePath(member)
	return err == nil && normalized == member
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func readResource(ctx context.Context, resource LocalResource, limit int64, keep bool) ([]byte, error) {
	if resource.Identity.Validate() != nil || !filepath.IsAbs(resource.Path) {
		return nil, ErrInvalidInput
	}
	file, err := os.Open(resource.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != resource.Identity.Size {
		return nil, ErrIntegrity
	}
	if limit > 0 && info.Size() > limit {
		return nil, ErrLimit
	}
	var h hash.Hash
	switch resource.Identity.Digest.Algorithm {
	case model.DigestMD5:
		h = md5.New()
	case model.DigestSHA1:
		h = sha1.New()
	case model.DigestSHA256:
		h = sha256.New()
	case model.DigestSHA384:
		h = sha512.New384()
	case model.DigestSHA512:
		h = sha512.New()
	default:
		return nil, ErrInvalidInput
	}
	var data bytes.Buffer
	var writer io.Writer = h
	if keep {
		writer = io.MultiWriter(h, &data)
	}
	// Reading at most the declared size plus one detects replacement/growth;
	// io.Copy never allocates in proportion to a large image container.
	reader := io.LimitReader(contextReader{ctx: ctx, reader: file}, resource.Identity.Size)
	n, err := io.Copy(writer, reader)
	if err != nil {
		return nil, err
	}
	var extra [1]byte
	extraN, extraErr := file.Read(extra[:])
	if extraErr != nil && extraErr != io.EOF {
		return nil, extraErr
	}
	if n != resource.Identity.Size || extraN != 0 || hex.EncodeToString(h.Sum(nil)) != resource.Identity.Digest.Value {
		return nil, ErrIntegrity
	}
	return data.Bytes(), nil
}

func decodeMetadata(ctx context.Context, original []byte, compressed bool, limit int64) ([]byte, error) {
	var data []byte = original
	if compressed {
		reader, err := gzip.NewReader(bytes.NewReader(original))
		if err != nil {
			return nil, fmt.Errorf("%w: gzip", ErrMalformedMetadata)
		}
		defer reader.Close()
		data, err = io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: reader}, limit+1))
		if err != nil {
			return nil, err
		}
	}
	if int64(len(data)) > limit {
		return nil, ErrLimit
	}
	if len(data) >= 2 && (bytes.Equal(data[:2], []byte{0xff, 0xfe}) || bytes.Equal(data[:2], []byte{0xfe, 0xff})) {
		if len(data)%2 != 0 {
			return nil, ErrMalformedMetadata
		}
		var order binary.ByteOrder = binary.LittleEndian
		if data[0] == 0xfe {
			order = binary.BigEndian
		}
		units := make([]uint16, (len(data)-2)/2)
		for i := range units {
			units[i] = order.Uint16(data[2+i*2:])
		}
		for i := 0; i < len(units); i++ {
			if units[i] >= 0xd800 && units[i] <= 0xdbff {
				if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
					return nil, ErrMalformedMetadata
				}
				i++
			} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
				return nil, ErrMalformedMetadata
			}
		}
		data = []byte(string(utf16.Decode(units)))
	}
	if int64(len(data)) > limit {
		return nil, ErrLimit
	}
	return bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), nil
}

// xmlNode is a bounded tree. Namespace comparisons are explicit in format
// parsers; a foreign extension with a familiar local name cannot supply facts.
type xmlNode struct {
	Name       xml.Name
	Attr       []xml.Attr
	Text       string
	Children   []*xmlNode
	textBuffer strings.Builder
}

func (n *xmlNode) attr(name string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attr {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
func (n *xmlNode) children(name string) []*xmlNode {
	if n == nil {
		return nil
	}
	var result []*xmlNode
	for _, c := range n.Children {
		if c.Name.Space == n.Name.Space && c.Name.Local == name {
			result = append(result, c)
		}
	}
	return result
}
func (n *xmlNode) child(name string) *xmlNode {
	children := n.children(name)
	if len(children) != 0 {
		return children[0]
	}
	return nil
}
func (n *xmlNode) text() string {
	if n == nil {
		return ""
	}
	return strings.TrimSpace(n.Text)
}

func parseXML(ctx context.Context, data []byte, limits Limits) (*xmlNode, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	// BOM-bearing UTF-16 was decoded above; encoding/xml may still observe its
	// original declaration. Other encodings remain unsupported, never guessed.
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "utf-16") || strings.EqualFold(charset, "utf-16le") || strings.EqualFold(charset, "utf-16be") {
			return input, nil
		}
		return nil, ErrMalformedMetadata
	}
	var root *xmlNode
	var stack []*xmlNode
	for count := 0; ; count++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if count >= limits.MaxXMLTokens {
			return nil, ErrLimit
		}
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: XML", ErrMalformedMetadata)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if len(stack) >= limits.MaxXMLDepth {
				return nil, ErrLimit
			}
			attributes := make(map[xml.Name]bool)
			for _, attr := range token.Attr {
				if attributes[attr.Name] {
					return nil, ErrMalformedMetadata
				}
				attributes[attr.Name] = true
			}
			node := &xmlNode{Name: token.Name, Attr: slices.Clone(token.Attr)}
			if len(stack) == 0 {
				if root != nil {
					return nil, ErrMalformedMetadata
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			// Comments and other tokens can split one element's character data
			// many times. Grow its buffer amortized-linearly, then expose the
			// immutable text once the element is complete.
			node := stack[len(stack)-1]
			node.Text = node.textBuffer.String()
			node.textBuffer.Reset()
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(token)) != "" {
					return nil, ErrMalformedMetadata
				}
			} else {
				stack[len(stack)-1].textBuffer.Write(token)
			}
		case xml.Directive:
			return nil, ErrMalformedMetadata
		case xml.ProcInst:
			if token.Target != "xml" || root != nil {
				return nil, ErrMalformedMetadata
			}
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, ErrMalformedMetadata
	}
	return root, nil
}

func singletonChildren(node *xmlNode, names ...string) error {
	for _, name := range names {
		if len(node.children(name)) > 1 {
			return fmt.Errorf("%w: duplicate %s", ErrConflictingMetadata, name)
		}
	}
	return nil
}

func (inv *Inventory) parseDocument(ctx context.Context, doc Document, data []byte, limits Limits, known map[model.PayloadIdentity]bool) error {
	if !supportedFormat(doc.Format) {
		inv.gap("unsupported-format", string(doc.Format), &doc.Reference)
		return nil
	}
	root, err := parseXML(ctx, data, limits)
	if err != nil {
		return err
	}
	switch doc.Format {
	case FormatWIMXML:
		return inv.parseWIM(root, doc.Reference)
	case FormatCompositionXML:
		return inv.parseComposition(root, doc.Reference, known)
	case FormatCBSXML:
		return inv.parseCBS(root, doc.Reference)
	case FormatAppxXML:
		return inv.parseAppx(root, doc.Reference)
	case FormatStoreLicenseXML:
		return inv.parseStoreLicense(root, doc.Reference)
	}
	return nil
}

func supportedFormat(format Format) bool {
	return format == FormatWIMXML || format == FormatCompositionXML || format == FormatCBSXML || format == FormatAppxXML || format == FormatStoreLicenseXML
}

func (inv *Inventory) gap(code, detail string, doc *DocumentReference) {
	inv.Gaps = append(inv.Gaps, Gap{Code: code, Detail: detail, Document: doc})
}
func (inv *Inventory) evidence(doc DocumentReference, selector string) Evidence {
	return Evidence{Source: inv.Source, Document: doc, Selector: selector}
}
func (inv *Inventory) architecture(arch model.Architecture) error {
	if arch != "" && arch != "neutral" && arch != inv.Source.Architecture {
		return fmt.Errorf("%w: source architecture %q versus metadata %q", ErrConflictingMetadata, inv.Source.Architecture, arch)
	}
	return nil
}
