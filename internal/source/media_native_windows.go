package source

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	native "golang.org/x/sys/windows"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabformat"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// NativeInspector borrows a pinned managed helper and an owned workspace. It
// never mounts images or runs source executables. Native output is bounded and
// every original source is reverified after its last use.
type NativeInspector struct {
	WIMLib    string
	Workspace *platform.Workspace
	Emit      model.Emit
	runner    platform.ProcessRunner
}

type mediaNativeRun struct {
	inspector NativeInspector
	root      string
	created   []string
	refs      []string
	disk      uint64
}

const mediaDocumentLimit = 8 << 20
const mediaTotalDocumentLimit = 32 << 20
const mediaStagingLimit = uint64(16 << 30)

func (n NativeInspector) Complete(ctx context.Context, inv *metadata.Inventory, files download.Materialized) (runErr error) {
	if ctx == nil || inv == nil || n.Workspace == nil || !filepath.IsAbs(n.WIMLib) || inv.Manifest.Validate() != nil || inv.Source != inv.Manifest.Source {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := mediaDocumentBudget(inv, nil); err != nil {
		return err
	}
	// Complete derives its candidate selection from the frozen base queries.
	selection := model.Selection{UpdateID: inv.Source.UpdateID, Architecture: inv.Source.Architecture, Language: inv.Source.Language}
	for _, q := range inv.Manifest.Queries {
		if !strings.EqualFold(q.Language, "neutral") && !slicesContainsFold(selection.Editions, q.Edition) {
			selection.Editions = append(selection.Editions, q.Edition)
		}
	}
	if len(selection.Editions) == 0 {
		return fmt.Errorf("%w: no frozen base-edition queries", ErrImplementationGap)
	}
	layout, err := DetectMedia(*inv, selection)
	if err != nil {
		return err
	}
	var token [12]byte
	if _, err = rand.Read(token[:]); err != nil {
		return err
	}
	r := mediaNativeRun{inspector: n, root: "source-inspection-" + hex.EncodeToString(token[:])}
	if err = n.Workspace.MkdirAll(r.root); err != nil {
		return err
	}
	r.created = append(r.created, r.root)
	defer func() {
		for i := len(r.created) - 1; i >= 0; i-- {
			if e := n.Workspace.Remove(r.created[i]); e != nil && !os.IsNotExist(e) {
				runErr = errors.Join(runErr, fmt.Errorf("owned source-inspection staging retained: %w", e))
			}
		}
	}()
	type sourceHandle struct {
		f        *os.File
		info     os.FileInfo
		resource metadata.LocalResource
		sha      string
	}
	var handles []sourceHandle
	defer func() {
		for _, h := range handles {
			if ctx.Err() == nil {
				sha, e := localsource.Verify(ctx, h.f, h.resource.Path, h.resource.Identity, h.info)
				if e != nil || sha != h.sha {
					runErr = errors.Join(runErr, metadata.ErrIntegrity, e)
				}
			}
			runErr = errors.Join(runErr, h.f.Close())
		}
	}()
	for _, p := range inv.Manifest.Payloads {
		file, ok := files[p.Identity]
		if !ok || file.Identity != p.Identity {
			return ErrInputIdentityChanged
		}
		if p.Identity.Encryption.Method != "" {
			return fmt.Errorf("%w: encrypted source requires an authenticated decryption adapter", ErrImplementationGap)
		}
		f, info, e := localsource.Open(file.Path, p.Identity)
		if e != nil {
			return e
		}
		sha, e := localsource.Verify(ctx, f, file.Path, p.Identity, info)
		if e != nil {
			f.Close()
			return e
		}
		if file.SHA256 != "" && file.SHA256 != sha {
			f.Close()
			return metadata.ErrIntegrity
		}
		handles = append(handles, sourceHandle{f, info, metadata.LocalResource{Identity: p.Identity, Path: file.Path}, sha})
		if strings.EqualFold(path.Ext(p.Destination), ".esd") || strings.EqualFold(path.Ext(p.Destination), ".wim") {
			r.refs = append(r.refs, "--ref="+file.Path)
		}
	}
	main := files[layout.Payload].Path
	// These paths distinguish media and Setup WinPE from a name, index or generic
	// recovery image. Verify exact regular-file records from actual WIM metadata.
	checks := []struct {
		index  int
		member string
	}{{layout.MediaIndex, "/setup.exe"}, {layout.MediaIndex, "/sources/setup.exe"}, {layout.MediaIndex, "/boot/BCD"}, {layout.MediaIndex, "/efi/microsoft/boot/BCD"}, {layout.PEIndex, "/Windows/System32/wpeinit.exe"}, {layout.PEIndex, "/Windows/System32/ntoskrnl.exe"}}
	if inv.Source.Architecture == "arm64" {
		checks = append(checks, struct {
			index  int
			member string
		}{layout.MediaIndex, "/efi/boot/bootaa64.efi"})
	} else if inv.Source.Architecture == "amd64" {
		checks = append(checks, struct {
			index  int
			member string
		}{layout.MediaIndex, "/efi/boot/bootx64.efi"})
	} else if inv.Source.Architecture == "x86" {
		checks = append(checks, struct {
			index  int
			member string
		}{layout.MediaIndex, "/efi/boot/bootia32.efi"})
	}
	var proof bytes.Buffer
	for _, check := range checks {
		body, _, e := r.wimFileRecord(ctx, main, check.index, check.member)
		if e != nil {
			return fmt.Errorf("%w: Setup/media image content requirement %s (index %d): %w", ErrImplementationGap, check.member, check.index, e)
		}
		proof.Write(body)
		file, _, e := r.extractWIMFile(ctx, main, check.index, check.member, 64<<20)
		if e != nil {
			return fmt.Errorf("%w: source media content stream %s: %w", ErrImplementationGap, check.member, e)
		}
		digest, e := observeMediaBinary(ctx, file, inv.Source.Architecture, strings.EqualFold(path.Base(check.member), "BCD"))
		if e != nil {
			return e
		}
		fmt.Fprintf(&proof, "verified stream SHA256 %s\n", digest)
	}
	sum := sha256.Sum256(proof.Bytes())
	ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: layout.Payload, Member: fmt.Sprintf("inspection/media-%d-pe-%d.txt", layout.MediaIndex, layout.PEIndex)}, SHA256: hex.EncodeToString(sum[:])}
	proofDoc := metadata.Document{Reference: ref, Original: proof.Bytes(), Provenance: "uupbuilder:verified-wimlib-exact-file-records-v1"}
	if err = mediaDocumentBudget(inv, []metadata.Document{proofDoc}); err != nil {
		return err
	}
	inv.Documents = append(inv.Documents, proofDoc)
	evidence := metadata.Evidence{Source: inv.Source, Document: ref, Selector: fmt.Sprintf("verified files in media image %d and Setup WinPE image %d", layout.MediaIndex, layout.PEIndex)}
	var pe metadata.Image
	for _, im := range inv.Images {
		if im.Resource.Payload == layout.Payload && im.Index == layout.PEIndex {
			pe = im
		}
	}
	inv.Roles = append(inv.Roles, metadata.RoleEvidence{Role: metadata.RoleSetup, Resource: pe.Resource, ImageIndex: pe.Index, Evidence: evidence})
	inv.Layouts = append(inv.Layouts, metadata.LayoutEvidence{Kind: metadata.LayoutFullMedia, Family: "three-image-uup-wim", Evidence: evidence})
	var osImage metadata.Image
	for _, im := range inv.Images {
		if im.Resource.Payload == layout.Payload && im.Index == layout.OSIndex {
			osImage = im
		}
	}
	mapping, e := r.readWIMFile(ctx, main, layout.OSIndex, "/Windows/servicing/Editions/EditionMappings.xml", mediaDocumentLimit)
	if e != nil {
		return fmt.Errorf("%w: actual EditionMappings.xml requires complete referenced WIM content: %w", ErrImplementationGap, e)
	}
	if e = addMediaEditionMappings(ctx, inv, osImage, mapping); e != nil {
		return e
	}
	for _, p := range inv.Manifest.Payloads {
		ext := strings.ToLower(path.Ext(p.Destination))
		if ext != ".cab" && ext != ".msu" {
			continue
		}
		file := files[p.Identity]
		if e = r.inspectUpdate(ctx, inv, p.Identity, file.Path, ext == ".msu"); e != nil {
			return e
		}
	}
	var sourceImages []metadata.Image
	for _, image := range inv.Images {
		if image.Resource.Payload == layout.Payload && slicesContainsFold(selection.Editions, image.Edition) {
			sourceImages = append(sourceImages, image)
		}
	}
	if err = bindMediaUpdateRelationships(inv, sourceImages...); err != nil {
		return err
	}
	if err = r.inspectSourceEdge(ctx, inv, files); err != nil {
		return fmt.Errorf("inspect source Edge.wim content: %w", err)
	}
	// Resolve only observations established above. Recovery and app absence stay
	// unexamined; excluded recovery does not need an invented absence assertion.
	var gaps []metadata.Gap
	for _, g := range inv.Gaps {
		if g.Code == "layout-unresolved" || g.Code == "edition-bases-unresolved" || g.Code == "role-unresolved" && strings.HasPrefix(g.Detail, "setup ") {
			continue
		}
		gaps = append(gaps, g)
	}
	inv.Gaps = gaps
	inv.Classification = metadata.ClassificationMetadataIncomplete
	if len(gaps) == 0 {
		inv.Classification = metadata.ClassificationSemanticInventory
	}
	return ctx.Err()
}

func slicesContainsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func (r *mediaNativeRun) run(ctx context.Context, exe string, args ...string) (platform.RunResult, error) {
	args = mediaProcessArguments(args)
	bounded, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	runner := r.inspector.runner
	if runner == nil {
		runner = platform.NewRunner()
	}
	out, err := runner.Run(bounded, platform.Invocation{Executable: exe, Arguments: args, Workspace: r.inspector.Workspace, JobID: r.inspector.Workspace.Identity().JobID, OperationID: "inspect-source", Cancellation: platform.CancelTerminateTree}, r.inspector.Emit)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	runErr := err
	if len(out.Stdout) >= 60<<10 || len(out.Stderr) >= 60<<10 {
		return out, mediaHelperFailure(exe, args, out, errors.Join(runErr, metadata.ErrLimit))
	}
	out.Stdout, err = decodeMediaText(out.Stdout)
	if err != nil {
		return out, mediaHelperFailure(exe, args, out, errors.Join(runErr, err))
	}
	out.Stderr, err = decodeMediaText(out.Stderr)
	if err != nil {
		return out, mediaHelperFailure(exe, args, out, errors.Join(runErr, err))
	}
	if runErr != nil {
		return out, mediaHelperFailure(exe, args, out, runErr)
	}
	return out, nil
}

// Keep extended names for handle-relative custody and local I/O. The managed
// command-line tools use their ordinary Win32 path parsers for process inputs,
// references and destinations; passing an extended input back into wimlib can
// turn its normalized filename into a rootless UNC basename.
func mediaProcessArguments(args []string) []string {
	out := slices.Clone(args)
	for i, arg := range out {
		prefix := ""
		value := arg
		if strings.HasPrefix(arg, "--ref=") {
			prefix = "--ref="
			value = strings.TrimPrefix(arg, prefix)
		} else if strings.HasPrefix(arg, "--dest-dir=") {
			prefix = "--dest-dir="
			value = strings.TrimPrefix(arg, prefix)
		} else if !strings.HasPrefix(arg, `\\?\`) {
			continue
		}
		if strings.HasPrefix(value, `\\?\UNC\`) {
			value = `\\` + strings.TrimPrefix(value, `\\?\UNC\`)
		} else {
			value = strings.TrimPrefix(value, `\\?\`)
		}
		out[i] = prefix + value
	}
	return out
}

func mediaHelperFailure(exe string, args []string, out platform.RunResult, err error) error {
	op := "inspection"
	if len(args) > 0 {
		op = args[0]
	}
	stdout, stderr := out.Stdout, out.Stderr
	if len(stdout) > 8192 {
		stdout = stdout[len(stdout)-8192:]
	}
	if len(stderr) > 8192 {
		stderr = stderr[len(stderr)-8192:]
	}
	return fmt.Errorf("read-only helper %s operation %q exit %d: %w; stdout %q; stderr %q", filepath.Base(exe), op, out.ExitCode, err, stdout, stderr)
}

func decodeMediaText(text string) (string, error) {
	b := []byte(text)
	if len(b) >= 2 && (b[0] == 0xff && b[1] == 0xfe || b[0] == 0xfe && b[1] == 0xff || len(b) > 3 && b[1] == 0 && b[3] == 0) {
		if len(b)%2 != 0 {
			return "", metadata.ErrMalformedMetadata
		}
		var order binary.ByteOrder = binary.LittleEndian
		if b[0] == 0xfe && b[1] == 0xff {
			order = binary.BigEndian
			b = b[2:]
		} else if b[0] == 0xff && b[1] == 0xfe {
			b = b[2:]
		}
		units := make([]uint16, len(b)/2)
		for i := range units {
			units[i] = order.Uint16(b[i*2:])
		}
		for i := 0; i < len(units); i++ {
			if units[i] >= 0xd800 && units[i] <= 0xdbff {
				if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
					return "", metadata.ErrMalformedMetadata
				}
				i++
			} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
				return "", metadata.ErrMalformedMetadata
			}
		}
		return string(utf16.Decode(units)), nil
	}
	return strings.TrimPrefix(text, "\ufeff"), nil
}

var mediaWIMSize = regexp.MustCompile(`(?m)^Uncompressed size = ([0-9]+) bytes\r?$`)

func (r *mediaNativeRun) wimFileRecord(ctx context.Context, file string, index int, member string) ([]byte, uint64, error) {
	args := append([]string{"dir", file, strconv.Itoa(index), "--path=" + member, "--one-file-only", "--detailed"}, r.refs...)
	out, err := r.run(ctx, r.inspector.WIMLib, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("WIM image %d member %q file record: %w", index, member, err)
	}
	text := out.Stdout
	if strings.Count(text, "Full Path           = ") != 1 || strings.Contains(text, "FILE_ATTRIBUTE_REPARSE_POINT is set") || strings.Contains(text, "FILE_ATTRIBUTE_DIRECTORY is set") || strings.Contains(text, "FILE_ATTRIBUTE_ENCRYPTED is set") || !strings.Contains(text, "Unnamed data stream:") {
		return nil, 0, metadata.ErrMalformedMetadata
	}
	var actual string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Full Path           = ") {
			actual = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "Full Path           = ")), `"`)
		}
	}
	if !strings.EqualFold(strings.ReplaceAll(actual, `\`, "/"), member) {
		return nil, 0, metadata.ErrIntegrity
	}
	match := mediaWIMSize.FindStringSubmatch(text)
	if len(match) != 2 {
		return nil, 0, fmt.Errorf("referenced stream bytes are unavailable")
	}
	size, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil || size == 0 {
		return nil, 0, metadata.ErrMalformedMetadata
	}
	return []byte(text), size, nil
}

func (r *mediaNativeRun) extractWIMFile(ctx context.Context, file string, index int, member string, limit uint64) (string, uint64, error) {
	_, size, err := r.wimFileRecord(ctx, file, index, member)
	if err != nil {
		return "", 0, err
	}
	if size > limit || size > mediaStagingLimit-r.disk {
		return "", 0, metadata.ErrLimit
	}
	dir := fmt.Sprintf("%s/f%04d", r.root, len(r.created))
	if err = r.inspector.Workspace.MkdirAll(dir); err != nil {
		return "", 0, err
	}
	r.created = append(r.created, dir)
	args := append([]string{"extract", file, strconv.Itoa(index), member, "--dest-dir=" + filepath.Join(r.inspector.Workspace.Path(), filepath.FromSlash(dir)), "--no-acls", "--no-attributes", "--no-globs"}, r.refs...)
	if _, err = r.run(ctx, r.inspector.WIMLib, args...); err != nil {
		return "", 0, fmt.Errorf("WIM image %d member %q extraction: %w", index, member, err)
	}
	rel := dir + "/" + path.Base(strings.ReplaceAll(member, `\`, "/"))
	r.created = append(r.created, rel)
	f, err := r.inspector.Workspace.OpenFile(rel, os.O_RDONLY, 0)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if err = checkMediaFile(f, size); err != nil {
		return "", 0, err
	}
	r.disk += size
	return filepath.Join(r.inspector.Workspace.Path(), filepath.FromSlash(rel)), size, nil
}

func checkMediaFile(file *os.File, size uint64) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != size {
		return metadata.ErrIntegrity
	}
	var nativeInfo native.ByHandleFileInformation
	if native.GetFileInformationByHandle(native.Handle(file.Fd()), &nativeInfo) != nil || nativeInfo.FileAttributes&native.FILE_ATTRIBUTE_REPARSE_POINT != 0 || nativeInfo.NumberOfLinks != 1 {
		return metadata.ErrIntegrity
	}
	return nil
}

func observeMediaBinary(ctx context.Context, file string, architecture model.Architecture, bcd bool) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	var h [64]byte
	if _, err = io.ReadFull(f, h[:]); err != nil {
		return "", metadata.ErrMalformedMetadata
	}
	if bcd {
		if string(h[:4]) != "regf" {
			return "", metadata.ErrMalformedMetadata
		}
	} else {
		if string(h[:2]) != "MZ" {
			return "", metadata.ErrMalformedMetadata
		}
		offset := int64(binary.LittleEndian.Uint32(h[60:]))
		if offset < 64 || offset > info.Size()-6 {
			return "", metadata.ErrMalformedMetadata
		}
		var pe [6]byte
		if _, err = f.ReadAt(pe[:], offset); err != nil || string(pe[:4]) != "PE\x00\x00" {
			return "", metadata.ErrMalformedMetadata
		}
		machine := binary.LittleEndian.Uint16(pe[4:])
		expected := map[model.Architecture]uint16{"x86": 0x14c, "amd64": 0x8664, "arm64": 0xaa64}
		if want, ok := expected[architecture]; !ok || machine != want {
			return "", fmt.Errorf("%w: source executable architecture does not match selected target", metadata.ErrConflictingMetadata)
		}
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	sum := sha256.New()
	buf := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		n, e := f.Read(buf)
		if n > 0 {
			sum.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func (r *mediaNativeRun) readWIMFile(ctx context.Context, file string, index int, member string, limit uint64) ([]byte, error) {
	name, size, err := r.extractWIMFile(ctx, file, index, member, limit)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, int64(size)+1))
	if err != nil || uint64(len(body)) != size {
		return nil, metadata.ErrIntegrity
	}
	return body, ctx.Err()
}

func addMediaEditionMappings(ctx context.Context, inv *metadata.Inventory, image metadata.Image, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(body) == 0 || len(body) > mediaDocumentLimit {
		return metadata.ErrLimit
	}
	var mapping struct {
		XMLName  xml.Name
		Editions []struct {
			Virtual             string `xml:"virtual,attr"`
			Name, ParentEdition string
		} `xml:"Edition"`
	}
	decoded, err := decodeMediaText(string(body))
	if err != nil {
		return err
	}
	if err = validateMediaXML(ctx, []byte(decoded)); err != nil {
		return err
	}
	if err := mediaXMLDecoder([]byte(decoded)).Decode(&mapping); err != nil || mapping.XMLName.Local != "WindowsEditions" || mapping.XMLName.Space != "" {
		return metadata.ErrMalformedMetadata
	}
	sum := sha256.Sum256(body)
	ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: image.Resource.Payload, Member: fmt.Sprintf("image-%d/Windows/servicing/Editions/EditionMappings.xml", image.Index)}, SHA256: hex.EncodeToString(sum[:])}
	doc := metadata.Document{Reference: ref, Original: bytes.Clone(body), Provenance: "uupbuilder:verified-wimlib-extracted-edition-mappings-v1"}
	if err = mediaDocumentBudget(inv, []metadata.Document{doc}); err != nil {
		return err
	}
	inv.Documents = append(inv.Documents, doc)
	seen := map[string]string{}
	for _, edition := range mapping.Editions {
		if !strings.EqualFold(edition.Virtual, "true") {
			continue
		}
		name, base := strings.TrimSpace(edition.Name), strings.TrimSpace(edition.ParentEdition)
		if name == "" || base == "" || strings.EqualFold(name, base) {
			return metadata.ErrMalformedMetadata
		}
		key := strings.ToLower(name)
		if old, ok := seen[key]; ok && !strings.EqualFold(old, base) {
			return metadata.ErrConflictingMetadata
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = base
		inv.EditionBases = append(inv.EditionBases, metadata.EditionBase{Edition: name, Base: base, Evidence: metadata.Evidence{Source: inv.Source, Document: ref, Selector: "/WindowsEditions/Edition[@virtual='true'][Name='" + name + "']/ParentEdition"}})
	}
	return nil
}

// CAB metadata inspection uses the existing strict framing ceilings. Modern
// large MSUs are WIM containers and take the independent streaming WIM route.
func (r *mediaNativeRun) inspectUpdate(ctx context.Context, inv *metadata.Inventory, id model.PayloadIdentity, file string, isMSU bool) (runErr error) {
	defer func() {
		if runErr != nil {
			runErr = fmt.Errorf("inspect source CBS/update %q: %w", id.Provenance.Name, runErr)
		}
	}()
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	var magic [8]byte
	_, err = io.ReadFull(f, magic[:])
	f.Close()
	if err != nil {
		return err
	}
	var docs []metadata.MetadataDocument
	if string(magic[:]) == "MSWIM\x00\x00\x00" {
		out, e := r.run(ctx, r.inspector.WIMLib, "dir", file, "1")
		if e != nil {
			return e
		}
		var nested []string
		for _, line := range strings.Split(out.Stdout, "\n") {
			member := strings.ReplaceAll(strings.TrimSpace(line), `\`, "/")
			if member == "/" || member == "" {
				continue
			}
			if !strings.HasPrefix(member, "/") {
				return metadata.ErrMalformedMetadata
			}
			valid, e := model.ValidateRelativePath(strings.TrimPrefix(member, "/"))
			if e != nil {
				return e
			}
			ext := strings.ToLower(path.Ext(valid))
			if ext == ".cab" || ext == ".wim" {
				nested = append(nested, "/"+valid)
			}
		}
		if len(nested) == 0 || len(nested) > 64 {
			return fmt.Errorf("%w: update WIM contains no bounded nested installer set", ErrImplementationGap)
		}
		for _, member := range nested {
			name, _, e := r.extractWIMFile(ctx, file, 1, member, mediaStagingLimit)
			if e != nil {
				return e
			}
			if strings.EqualFold(path.Ext(member), ".wim") {
				body, e := r.readWIMFile(ctx, name, 1, "/update.mum", mediaDocumentLimit)
				if e != nil {
					return fmt.Errorf("nested update WIM member %q: %w", member, e)
				}
				docs = append(docs, metadata.MetadataDocument{Resource: metadata.ResourceReference{Payload: id, Member: strings.TrimPrefix(member, "/") + "/update.mum"}, Format: metadata.FormatCBSXML, Original: body, Provenance: "uupbuilder:verified-nested-wim-cbs-v1"})
			} else {
				more, e := r.cabCBS(ctx, id, name, strings.TrimPrefix(member, "/")+"/")
				if e != nil {
					return fmt.Errorf("nested update CAB member %q: %w", member, e)
				}
				docs = append(docs, more...)
			}
		}
	} else if string(magic[:4]) == "MSCF" {
		more, e := r.cabCBS(ctx, id, file, "")
		if e != nil {
			return e
		}
		docs = more
	} else {
		return fmt.Errorf("%w: update container has an unsupported signature", ErrImplementationGap)
	}
	if len(docs) == 0 {
		if isMSU {
			return fmt.Errorf("%w: update source has no inspected CBS installation identity", ErrImplementationGap)
		}
		return nil
	}
	return r.addCBS(ctx, inv, id, file, docs, isMSU)
}

func (r *mediaNativeRun) cabCBS(ctx context.Context, id model.PayloadIdentity, file, prefix string) ([]metadata.MetadataDocument, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	table, err := cabformat.Inspect(ctx, f, uint64(info.Size()), cabformat.Limits{})
	if err != nil {
		return nil, fmt.Errorf("%w: bounded CBS CAB framing: %w", ErrImplementationGap, err)
	}
	var docs []metadata.MetadataDocument
	for _, member := range table.Members {
		// The top-level CBS manifest is the installation identity. Enumerating all
		// component manifests would invent separately installable updates.
		if !strings.EqualFold(member.Name, "update.mum") {
			continue
		}
		if member.Size > mediaDocumentLimit {
			return nil, metadata.ErrLimit
		}
		dir := fmt.Sprintf("%s/c%04d", r.root, len(r.created))
		if err = r.inspector.Workspace.MkdirAll(dir); err != nil {
			return nil, err
		}
		r.created = append(r.created, dir)
		system, e := native.GetSystemDirectory()
		if e != nil {
			return nil, e
		}
		// expand.exe does not recognize the extended namespace as an existing
		// destination directory; it may report this on stdout with exit code 0.
		// The process already runs inside the held owned workspace. Its validated
		// logical directory avoids that parser limitation without changing custody.
		result, extractErr := r.run(ctx, filepath.Join(system, "expand.exe"), "-F:"+member.Name, strings.TrimPrefix(file, `\\?\`), filepath.FromSlash(dir))
		if extractErr != nil {
			return nil, fmt.Errorf("CBS source %q member %q extraction: %w; stdout %q; stderr %q", id.Provenance.Name, member.Name, extractErr, result.Stdout, result.Stderr)
		}
		directory, openErr := r.inspector.Workspace.OpenFile(dir, os.O_RDONLY, 0)
		if openErr != nil {
			return nil, openErr
		}
		entries, listErr := directory.ReadDir(2)
		closeErr := directory.Close()
		if listErr != nil && listErr != io.EOF || closeErr != nil || len(entries) != 1 {
			return nil, fmt.Errorf("CBS source %q member %q produced an unexpected file set: %w", id.Provenance.Name, member.Name, metadata.ErrMalformedMetadata)
		}
		actual := entries[0].Name()
		// A single-file cabinet retains the input cache basename in expand.exe.
		// Accept only that documented case, then verify the exact declared size
		// and regular owned file before reading its source-bound original bytes.
		if !strings.EqualFold(actual, member.Name) && !(len(table.Members) == 1 && strings.EqualFold(actual, filepath.Base(file))) {
			return nil, fmt.Errorf("CBS source %q member %q produced unexpected name %q: %w", id.Provenance.Name, member.Name, actual, metadata.ErrMalformedMetadata)
		}
		rel := dir + "/" + actual
		r.created = append(r.created, rel)
		out, e := r.inspector.Workspace.OpenFile(rel, os.O_RDONLY, 0)
		if e != nil {
			return nil, fmt.Errorf("CBS source %q member %q output: %w; stdout %q; stderr %q", id.Provenance.Name, member.Name, e, result.Stdout, result.Stderr)
		}
		if e = checkMediaFile(out, member.Size); e != nil {
			out.Close()
			return nil, e
		}
		body, e := io.ReadAll(io.LimitReader(out, int64(member.Size)+1))
		closeErr = out.Close()
		if e != nil || closeErr != nil || uint64(len(body)) != member.Size {
			return nil, metadata.ErrIntegrity
		}
		docs = append(docs, metadata.MetadataDocument{Resource: metadata.ResourceReference{Payload: id, Member: prefix + member.Name}, Format: metadata.FormatCBSXML, Original: body, Provenance: "uupbuilder:verified-cab-cbs-v1"})
	}
	return docs, nil
}

type mediaDocumentsProvider struct{ documents []metadata.MetadataDocument }

func (p mediaDocumentsProvider) Inspect(ctx context.Context, _ metadata.LocalResource, _ metadata.Limits) (metadata.ProviderResult, error) {
	return metadata.ProviderResult{Documents: p.documents}, ctx.Err()
}

func (r *mediaNativeRun) addCBS(ctx context.Context, inv *metadata.Inventory, id model.PayloadIdentity, file string, docs []metadata.MetadataDocument, isMSU bool) error {
	var proposed []metadata.Document
	for _, doc := range docs {
		proposed = append(proposed, metadata.Document{Original: doc.Original})
	}
	if err := mediaDocumentBudget(inv, proposed); err != nil {
		return err
	}
	// The containing file was verified before and will be reverified after every
	// native observation; parse original CBS bytes through the bounded parser.
	// Reuse Inspect's full evidence validation using source-bound documents. The
	// resource path is borrowed from the already verified input, never serialized.
	parsed, err := metadata.Inspect(ctx, metadata.InspectRequest{Source: inv.Source, Manifest: inv.Manifest, Inspections: []metadata.Inspection{{Resource: metadata.LocalResource{Identity: id, Path: file}, Provider: mediaDocumentsProvider{docs}}}})
	if err != nil {
		return err
	}
	if err = observeMediaCBSPackageParents(ctx, &parsed); err != nil {
		return err
	}
	inv.Documents = append(inv.Documents, parsed.Documents...)
	inv.Packages = append(inv.Packages, parsed.Packages...)
	if len(parsed.Packages) == 0 {
		return fmt.Errorf("%w: CBS package schema not supported", ErrImplementationGap)
	}
	var update metadata.Update
	for _, pack := range parsed.Packages {
		kind, err := mediaUpdateKind(pack)
		if err != nil {
			// Base, language and FoD content also have update.mum. Their observed
			// package identities are retained without inventing update operations.
			if !isMSU && !strings.HasPrefix(strings.ToLower(pack.Identity.Name), "package_for_") {
				continue
			}
			return err
		}
		if update.ID == "" || kind != metadata.UpdateServicingStack {
			update.ID = pack.Identifier
			update.Kind = kind
			update.Evidence = pack.Evidence
		}
		target, targetErr := mediaUpdateTarget(&parsed, pack)
		if targetErr != nil {
			return targetErr
		}
		if len(update.Packages) > 0 && update.Target != target {
			return fmt.Errorf("%w: source container has ambiguous OS/WinRE update scopes", ErrImplementationGap)
		}
		update.Target = target
		update.Packages = append(update.Packages, pack.Identity)
	}
	if update.ID == "" {
		if !isMSU {
			return nil
		}
		return metadata.ErrMalformedMetadata
	}
	update.Resource = metadata.ResourceReference{Payload: id}
	update.Format = metadata.UpdateCAB
	if isMSU {
		update.Format = metadata.UpdateMSU
	}
	for _, old := range inv.Updates {
		if strings.EqualFold(old.ID, update.ID) {
			return metadata.ErrConflictingMetadata
		}
	}
	inv.Updates = append(inv.Updates, update)
	return nil
}

func validateMediaXML(ctx context.Context, body []byte) error {
	if len(body) > mediaDocumentLimit {
		return metadata.ErrLimit
	}
	d := mediaXMLDecoder(body)
	depth, tokens := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return metadata.ErrMalformedMetadata
		}
		tokens++
		if tokens > 100000 {
			return metadata.ErrLimit
		}
		switch token.(type) {
		case xml.StartElement:
			start := token.(xml.StartElement)
			attributes := map[xml.Name]bool{}
			for _, attr := range start.Attr {
				if attributes[attr.Name] {
					return metadata.ErrMalformedMetadata
				}
				attributes[attr.Name] = true
			}
			depth++
			if depth > 64 {
				return metadata.ErrLimit
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return metadata.ErrMalformedMetadata
		}
	}
	return nil
}

func mediaXMLDecoder(body []byte) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(body))
	d.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "utf-16") || strings.EqualFold(charset, "utf-16le") || strings.EqualFold(charset, "utf-16be") {
			return input, nil
		}
		return nil, metadata.ErrMalformedMetadata
	}
	return d
}

type mediaCBSIdentity struct {
	Name         string             `xml:"name,attr"`
	Version      string             `xml:"version,attr"`
	Architecture model.Architecture `xml:"processorArchitecture,attr"`
	Language     string             `xml:"language,attr"`
	Token        string             `xml:"publicKeyToken,attr"`
}

func (i mediaCBSIdentity) identity() metadata.PackageIdentity {
	return metadata.PackageIdentity{Name: i.Name, Version: i.Version, Architecture: i.Architecture, Language: i.Language, PublicKeyToken: i.Token}
}
func observeMediaCBSPackageParents(ctx context.Context, inv *metadata.Inventory) error {
	for _, doc := range inv.Documents {
		if doc.Format != metadata.FormatCBSXML {
			continue
		}
		text, err := decodeMediaText(string(doc.Original))
		if err != nil {
			return err
		}
		if err = validateMediaXML(ctx, []byte(text)); err != nil {
			return err
		}
		var cbs struct {
			Package struct {
				Parents []struct {
					Identities []mediaCBSIdentity `xml:"urn:schemas-microsoft-com:asm.v3 assemblyIdentity"`
				} `xml:"urn:schemas-microsoft-com:asm.v3 parent"`
			} `xml:"urn:schemas-microsoft-com:asm.v3 package"`
		}
		if err = mediaXMLDecoder([]byte(text)).Decode(&cbs); err != nil {
			return err
		}
		for i := range inv.Packages {
			pack := &inv.Packages[i]
			if pack.Evidence.Document != doc.Reference {
				continue
			}
			for _, parent := range cbs.Package.Parents {
				for _, identity := range parent.Identities {
					if identity.Name == "" {
						return metadata.ErrMalformedMetadata
					}
					dependency := metadata.PackageDependency{Identity: identity.identity(), Type: "parent"}
					if !slices.Contains(pack.Dependencies, dependency) {
						pack.Dependencies = append(pack.Dependencies, dependency)
					}
				}
			}
		}
	}
	return nil
}

func bindMediaUpdateRelationships(inv *metadata.Inventory, images ...metadata.Image) error {
	groupsByDocument, err := mediaCBSParentGroups(inv)
	if err != nil {
		return err
	}
	if len(images) == 0 {
		images = inv.Images
	}
	for i := range inv.Updates {
		update := &inv.Updates[i]
		if update.Target != "" && update.Target != metadata.RoleOS && update.Target != metadata.RoleWinRE {
			return metadata.ErrInvalidEvidence
		}
		if update.Target == metadata.RoleWinRE {
			if err := mediaVerifyWinREUpdate(inv, *update); err != nil {
				return err
			}
			continue
		}
		var editions []string
		for _, pack := range inv.Packages {
			if !slices.Contains(update.Packages, pack.Identity) {
				continue
			}
			groups := groupsByDocument[pack.Evidence.Document]
			if len(groups) == 0 {
				var parents []metadata.PackageIdentity
				for _, dep := range pack.Dependencies {
					if dep.Type == "parent" {
						parents = append(parents, dep.Identity)
					}
				}
				if len(parents) > 0 {
					groups = append(groups, mediaCBSParent{Identities: parents})
				}
			}
			for _, group := range groups {
				parentContext := mediaCBSParentContext(update.ID, pack, group)
				var groupEditions []string
				var predecessor string
				for _, parent := range group.Identities {
					name := parent.Name
					if strings.HasPrefix(name, "Microsoft-Windows-") && strings.HasSuffix(name, "Edition") {
						edition := strings.TrimSuffix(strings.TrimPrefix(name, "Microsoft-Windows-"), "Edition")
						if edition != "" && !slicesContainsFold(groupEditions, edition) {
							groupEditions = append(groupEditions, edition)
						}
					}
					for j, prior := range inv.Updates {
						if prior.Target != "" && prior.Target != metadata.RoleOS {
							continue
						}
						if i == j {
							continue
						}
						if slices.Contains(prior.Packages, parent) && (predecessor == "" || prior.ID < predecessor) {
							predecessor = prior.ID
						}
					}
				}
				// Parent identities in one CBS <parent> are alternatives. A known
				// predecessor satisfies that group; otherwise retain the complete
				// edition applicability restriction, including unselected editions.
				if predecessor != "" {
					if len(groupEditions) > 0 {
						return fmt.Errorf("%w: %s: mixed CBS edition/predecessor parent alternatives require an applicability-expression adapter", ErrImplementationGap, parentContext)
					}
					if !slicesContainsFold(update.Predecessors, predecessor) {
						update.Predecessors = append(update.Predecessors, predecessor)
					}
				} else if len(groupEditions) > 0 {
					if err := bindMediaCheckpointBaseline(inv, i, pack, group, groupsByDocument, images); err != nil {
						return fmt.Errorf("%s: %w", parentContext, err)
					}
					if len(editions) == 0 {
						editions = groupEditions
					} else {
						var intersection []string
						for _, edition := range editions {
							if slicesContainsFold(groupEditions, edition) {
								intersection = append(intersection, edition)
							}
						}
						if len(intersection) == 0 {
							return fmt.Errorf("%w: %s: CBS parent groups have incompatible edition applicability", ErrImplementationGap, parentContext)
						}
						editions = intersection
					}
				} else {
					return fmt.Errorf("%w: %s: CBS parent alternatives have no inspected predecessor or installed-base package evidence", ErrImplementationGap, parentContext)
				}
			}
			for _, dep := range pack.Dependencies {
				if dep.Type == "parent" {
					continue
				}
				matched := slices.Contains(update.Packages, dep.Identity)
				for j, prior := range inv.Updates {
					if prior.Target != "" && prior.Target != metadata.RoleOS {
						continue
					}
					if i == j {
						continue
					}
					for _, identity := range prior.Packages {
						if identity == dep.Identity {
							matched = true
							if !slicesContainsFold(update.Predecessors, prior.ID) {
								update.Predecessors = append(update.Predecessors, prior.ID)
							}
						}
					}
				}
				if !matched && dep.Type != "parent" && !strings.EqualFold(dep.Type, "optional") {
					return fmt.Errorf("%w: update %s package %s document %s: required CBS dependency %+v has no inspected update or installed-base package evidence", ErrImplementationGap, update.ID, pack.Identity.Name, pack.Evidence.Document.Resource.Member, dep.Identity)
				}
			}
		}
		update.Editions = editions
	}
	byID := map[string]metadata.Update{}
	for _, update := range inv.Updates {
		if update.Target != "" && update.Target != metadata.RoleOS {
			continue
		}
		byID[strings.ToLower(update.ID)] = update
	}
	var reaches func(string, string, map[string]bool) bool
	reaches = func(from, want string, seen map[string]bool) bool {
		key := strings.ToLower(from)
		if seen[key] {
			return false
		}
		seen[key] = true
		for _, dep := range byID[key].Predecessors {
			if strings.EqualFold(dep, want) || reaches(dep, want, seen) {
				return true
			}
		}
		return false
	}
	// Multiple rollup packages require explicit CBS predecessors. Their filename
	// or enumeration order is not a checkpoint installation rule.
	for i, a := range inv.Updates {
		if a.Kind != metadata.UpdateCumulative || a.Target != "" && a.Target != metadata.RoleOS {
			continue
		}
		for j, b := range inv.Updates {
			if i >= j || b.Kind != metadata.UpdateCumulative || b.Target != "" && b.Target != metadata.RoleOS {
				continue
			}
			sameFamily := false
			for _, x := range a.Packages {
				for _, y := range b.Packages {
					sameFamily = sameFamily || x.Name == y.Name && x.Architecture == y.Architecture && x.PublicKeyToken == y.PublicKeyToken && x.Language == y.Language
				}
			}
			if sameFamily && !reaches(a.ID, b.ID, map[string]bool{}) && !reaches(b.ID, a.ID, map[string]bool{}) {
				return fmt.Errorf("%w: cumulative updates %s %+v and %s %+v require an inspected CBS predecessor relationship", ErrImplementationGap, a.ID, a.Packages, b.ID, b.Packages)
			}
		}
	}
	return nil
}

func mediaUpdateKind(pack metadata.Package) (metadata.UpdateKind, error) {
	name := strings.ToLower(pack.Identity.Name)
	release := strings.ToLower(strings.Join(strings.Fields(pack.ReleaseType), ""))
	switch {
	case strings.HasPrefix(name, "package_for_servicingstack"):
		return metadata.UpdateServicingStack, nil
	case strings.HasPrefix(name, "package_for_rollupfix"), strings.Contains(name, "dotnetrollup"):
		return metadata.UpdateCumulative, nil
	case release == "featurepack" && strings.Contains(name, "enablement"):
		return metadata.UpdateEnablement, nil
	}
	// CBS's installation wrapper and declared release type establish an ordinary
	// servicing update without asserting cumulative or enablement semantics.
	// Microsoft distinguishes these release classes from FoD/language/base data:
	// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismreleasetype-enumeration
	if strings.HasPrefix(name, "package_for_") {
		switch release {
		case "update", "criticalupdate", "securityupdate", "softwareupdate", "hotfix", "updaterollup", "servicepack":
			return metadata.UpdateRegular, nil
		}
	}
	return "", fmt.Errorf("%w: CBS installation identity %s/%s has no update-kind adapter", ErrImplementationGap, pack.Identity.Name, pack.ReleaseType)
}

func (r *mediaNativeRun) listWIMPaths(ctx context.Context, file string, index int) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	runner := r.inspector.runner
	if runner == nil {
		runner = platform.NewRunner()
	}
	var captured strings.Builder
	var mu sync.Mutex
	overflow := false
	out, err := runner.Run(bounded, platform.Invocation{Executable: r.inspector.WIMLib, Arguments: mediaProcessArguments([]string{"dir", file, strconv.Itoa(index)}), Workspace: r.inspector.Workspace, JobID: r.inspector.Workspace.Identity().JobID, OperationID: "inspect-source-directory", Cancellation: platform.CancelTerminateTree}, func(event model.Event) {
		if r.inspector.Emit != nil {
			r.inspector.Emit(event)
		}
		if event.Kind != model.EventLog {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if len(event.Message) > 8<<20-captured.Len() {
			overflow = true
			return
		}
		captured.WriteString(event.Message)
	})
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		out.Stdout, _ = decodeMediaText(out.Stdout)
		out.Stderr, _ = decodeMediaText(out.Stderr)
		return "", mediaHelperFailure(r.inspector.WIMLib, []string{"dir", file, strconv.Itoa(index)}, out, err)
	}
	if overflow {
		return "", metadata.ErrLimit
	}
	if captured.Len() == 0 {
		if len(out.Stdout) >= 60<<10 {
			return "", metadata.ErrLimit
		}
		return decodeMediaText(out.Stdout)
	}
	return decodeMediaText(captured.String())
}

func (r *mediaNativeRun) inspectSourceEdge(ctx context.Context, inv *metadata.Inventory, files download.Materialized) error {
	for _, payload := range inv.Manifest.Payloads {
		if !strings.EqualFold(path.Base(payload.Destination), "Edge.wim") {
			continue
		}
		var images []metadata.Image
		for _, image := range inv.Images {
			if image.Resource.Payload == payload.Identity {
				images = append(images, image)
			}
		}
		if len(images) != 1 || !strings.EqualFold(images[0].Name, "EdgeContent") {
			return fmt.Errorf("%w: source Edge WIM image semantics are not recognized", ErrImplementationGap)
		}
		file := files[payload.Identity].Path
		listing, err := r.listWIMPaths(ctx, file, images[0].Index)
		if err != nil {
			return err
		}
		samples, err := mediaEdgeSamples(listing)
		if err != nil {
			return err
		}
		var proof bytes.Buffer
		for _, sample := range samples {
			record, _, e := r.wimFileRecord(ctx, file, images[0].Index, "/"+sample)
			if e != nil {
				return e
			}
			proof.Write(record)
		}
		sum := sha256.Sum256(proof.Bytes())
		ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: payload.Identity, Member: "inspection/edge-content.txt"}, SHA256: hex.EncodeToString(sum[:])}
		doc := metadata.Document{Reference: ref, Original: proof.Bytes(), Provenance: "uupbuilder:verified-edge-content-wim-records-v1"}
		if err = mediaDocumentBudget(inv, []metadata.Document{doc}); err != nil {
			return err
		}
		inv.Documents = append(inv.Documents, doc)
		if inv.SourceEdge != nil {
			return metadata.ErrConflictingMetadata
		}
		resource := metadata.ResourceReference{Payload: payload.Identity}
		inv.SourceEdge = &resource
	}
	return nil
}

func mediaEdgeSamples(listing string) ([]string, error) {
	roots := map[string]bool{}
	represented := map[string]bool{}
	seen := map[string]bool{}
	var samples []string
	for _, line := range strings.Split(listing, "\n") {
		name := strings.ReplaceAll(strings.TrimSpace(line), `\`, "/")
		if name == "" || name == "/" {
			continue
		}
		if !strings.HasPrefix(name, "/") {
			continue
		}
		name = strings.TrimPrefix(name, "/")
		if clean, err := model.ValidateRelativePath(name); err != nil || clean != name {
			return nil, metadata.ErrMalformedMetadata
		}
		parts := strings.Split(name, "/")
		root := strings.ToLower(parts[0])
		switch root {
		case "edge", "edgecore", "edgeupdate", "edgewebview":
		default:
			continue
		}
		roots[root] = true
		match := strings.EqualFold(name, "Edge/Application/msedge.exe") || strings.EqualFold(name, "EdgeUpdate/MicrosoftEdgeUpdate.exe")
		if root == "edgecore" && len(parts) == 3 && strings.EqualFold(parts[2], "msedge.exe") {
			match = mediaVersionDirectory(parts[1])
		}
		if root == "edgewebview" && len(parts) == 4 && strings.EqualFold(parts[1], "Application") && strings.EqualFold(parts[3], "msedgewebview2.exe") {
			match = mediaVersionDirectory(parts[2])
		}
		if match {
			key := strings.ToLower(name)
			if seen[key] {
				return nil, metadata.ErrConflictingMetadata
			}
			seen[key] = true
			represented[root] = true
			samples = append(samples, name)
		}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: Edge WIM has no inspected browser content", ErrImplementationGap)
	}
	for root := range roots {
		if !represented[root] {
			return nil, fmt.Errorf("%w: Edge WIM root %s has no actual executable record", ErrImplementationGap, root)
		}
	}
	slices.Sort(samples)
	return samples, nil
}
func mediaVersionDirectory(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func mediaDocumentBudget(inv *metadata.Inventory, proposed []metadata.Document) error {
	if len(inv.Documents)+len(proposed) > mediaInventoryDocumentLimit {
		return metadata.ErrLimit
	}
	total := 0
	for _, docs := range [][]metadata.Document{inv.Documents, proposed} {
		for _, doc := range docs {
			cost, err := mediaDocumentBytes(doc)
			if err != nil {
				return err
			}
			if cost > mediaTotalDocumentLimit-total {
				return metadata.ErrLimit
			}
			total += cost
		}
	}
	return nil
}
