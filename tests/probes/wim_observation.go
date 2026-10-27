package probes

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"uupbuilder/internal/model"
)

type WIMObservation struct {
	Content        []byte `json:"-"`
	ExpectedSHA256 string `json:"expected_sha256"`
	MemberSHA1     string `json:"member_sha1"`
	MetadataSHA1   string `json:"metadata_sha1"`
	ContentBlobs   int    `json:"content_blobs"`
}

// This probe recognizes only the observed single-part WIM 0xe00 variant with
// one single-chunk metadata resource and one single-chunk LZMS solid resource.
// The author format descriptions identify lookup hashes as SHA1; embedded
// [sha256] manifest sections independently identify normalized file SHA256s.
// No content path from the source is used as a filesystem destination.
func extractObservedWIM(ctx context.Context, body []byte, member string, decompress func(context.Context, []byte, int) ([]byte, error)) (WIMObservation, error) {
	var result WIMObservation
	fail := func(text string) (WIMObservation, error) { return result, errors.New(text) }
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if _, err := model.ValidateRelativePath(member); err != nil {
		return result, err
	}
	if strings.ContainsAny(member, "/\\") {
		return fail("one flat WIM member required")
	}
	if len(body) < 208 || len(body) > 1<<20 || string(body[:8]) != "MSWIM\x00\x00\x00" || le.Uint32(body[8:]) != 208 || le.Uint32(body[12:]) != 0xe00 || le.Uint32(body[16:]) != 0x80002 {
		return fail("unimplemented WIM header/version/compression variant")
	}
	chunk := uint64(le.Uint32(body[20:]))
	if chunk == 0 || chunk > 1<<20 || le.Uint16(body[40:]) != 1 || le.Uint16(body[42:]) != 1 || le.Uint32(body[44:]) != 1 || le.Uint32(body[120:]) != 0 {
		return fail("unimplemented WIM split/image/chunk/boot variant")
	}
	lookup := readWIMResource(body[48:72])
	if lookup.flags != 2 || lookup.size != lookup.original || lookup.size == 0 || lookup.size%50 != 0 || lookup.size/50 > 4096 {
		return fail("invalid bounded WIM lookup table")
	}
	table, err := wimRegion(body, lookup.offset, lookup.size)
	if err != nil {
		return result, err
	}
	intervals := []wimResource{{size: 208}, lookup}
	// XML/integrity resources are retained source facts, not interpreted as
	// image-role or signature proof. Validate their extents before decompression.
	for _, at := range []int{72, 96, 124} {
		r := readWIMResource(body[at : at+24])
		if r.size == 0 {
			if r.offset != 0 || r.original != 0 || r.flags != 0 {
				return fail("invalid empty WIM header resource")
			}
			continue
		}
		if _, err := wimRegion(body, r.offset, r.size); err != nil {
			return result, err
		}
		intervals = append(intervals, r)
	}
	var metadata, solid wimResource
	var blobs []wimResource
	for at := 0; at < len(table); at += 50 {
		r := readWIMResource(table[at : at+24])
		r.hash = hex.EncodeToString(table[at+30 : at+50])
		r.references = le.Uint32(table[at+26:])
		if le.Uint16(table[at+24:]) != 1 {
			return fail("unimplemented cross-part WIM resource")
		}
		switch {
		case r.flags == 6:
			if metadata.size != 0 || r.original == 0 || r.original > chunk || r.references != 1 {
				return fail("unimplemented metadata resource shape")
			}
			metadata = r
		case r.flags == 16 && r.original == 0x100000000:
			if solid.size != 0 {
				return fail("multiple solid WIM resources unimplemented")
			}
			solid = r
		case r.flags == 16 && r.original == 0:
			if r.size == 0 || r.references == 0 {
				return fail("invalid solid blob identity")
			}
			blobs = append(blobs, r)
		default:
			return fail("unimplemented WIM resource flags")
		}
	}
	if metadata.size == 0 || solid.size < 21 || len(blobs) == 0 {
		return fail("metadata/solid/content closure missing")
	}
	for _, r := range []wimResource{metadata, solid} {
		if _, err := wimRegion(body, r.offset, r.size); err != nil {
			return result, err
		}
		intervals = append(intervals, r)
	}
	for i, a := range intervals {
		for _, b := range intervals[i+1:] {
			if a.offset < b.offset+b.size && b.offset < a.offset+a.size {
				return fail("overlapping WIM source resources")
			}
		}
	}
	expand := func(input []byte, size uint64) ([]byte, error) {
		if len(input) == 0 || len(input) > 1<<20 || size == 0 || size > 1<<20 {
			return nil, errors.New("WIM decompression bound exceeded")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out, err := decompress(ctx, input, int(size))
		if err != nil {
			return nil, err
		}
		if uint64(len(out)) != size {
			return nil, errors.New("WIM decompressor returned wrong size")
		}
		return out, ctx.Err()
	}
	metaInput, _ := wimRegion(body, metadata.offset, metadata.size)
	meta, err := expand(metaInput, metadata.original)
	if err != nil {
		return result, err
	}
	mh := sha1.Sum(meta)
	result.MetadataSHA1 = hex.EncodeToString(mh[:])
	if result.MetadataSHA1 != metadata.hash {
		return fail("WIM metadata expected SHA1 mismatch")
	}
	solidInput, _ := wimRegion(body, solid.offset, solid.size)
	usize := le.Uint64(solidInput)
	solidChunk := uint64(le.Uint32(solidInput[8:]))
	compression := le.Uint32(solidInput[12:])
	compressedSize := uint64(le.Uint32(solidInput[16:]))
	if usize == 0 || usize > 1<<20 || solidChunk < usize || solidChunk > 1<<30 || compression != 3 || compressedSize == 0 || compressedSize != uint64(len(solidInput))-20 {
		return fail("unimplemented/malformed single LZMS solid chunk")
	}
	raw, err := expand(solidInput[20:], usize)
	if err != nil {
		return result, err
	}
	content := map[string][]byte{}
	references := map[string]uint32{}
	for _, blob := range blobs {
		b, err := wimRegion(raw, blob.offset, blob.size)
		if err != nil {
			return result, err
		}
		h := sha1.Sum(b)
		hash := hex.EncodeToString(h[:])
		if hash != blob.hash {
			return fail("WIM content expected SHA1 mismatch")
		}
		if _, exists := content[hash]; exists {
			return fail("duplicate WIM content hash")
		}
		content[hash] = b
		references[hash] = blob.references
	}
	members, err := inspectFlatWIMMetadata(meta, content, references)
	if err != nil {
		return result, err
	}
	selected, ok := members[strings.ToLower(member)]
	if !ok {
		return fail("requested member missing from actual WIM metadata")
	}
	manifest, ok := members["$filehashes$.dat"]
	if !ok {
		return fail("source-embedded explicit SHA256 manifest missing")
	}
	expected, size, err := sourceManifestSHA256(manifest.data, member)
	if err != nil {
		return result, err
	}
	measured := sha256.Sum256(selected.data)
	if size != uint64(len(selected.data)) || expected != hex.EncodeToString(measured[:]) {
		return fail("source-embedded expected SHA256/size mismatch")
	}
	result.Content = append([]byte(nil), selected.data...)
	result.ExpectedSHA256 = expected
	result.MemberSHA1 = selected.hash
	result.ContentBlobs = len(blobs)
	return result, nil
}

var le = binary.LittleEndian

type wimResource struct {
	size, offset, original uint64
	flags                  byte
	hash                   string
	references             uint32
}

func readWIMResource(b []byte) wimResource {
	return wimResource{size: le.Uint64(b) & 0x00ffffffffffffff, flags: b[7], offset: le.Uint64(b[8:]), original: le.Uint64(b[16:])}
}
func wimRegion(b []byte, offset, size uint64) ([]byte, error) {
	if offset > uint64(len(b)) || size > uint64(len(b))-offset {
		return nil, errors.New("WIM resource exceeds actual bytes")
	}
	return b[int(offset):int(offset+size)], nil
}

type wimMember struct {
	data []byte
	hash string
}

func inspectFlatWIMMetadata(metadata []byte, content map[string][]byte, references map[string]uint32) (map[string]wimMember, error) {
	if len(metadata) < 8 {
		return nil, errors.New("WIM security header missing")
	}
	security := uint64(le.Uint32(metadata))
	// The observed zero-entry table writes total_length=0 but still occupies
	// the eight-byte security header; no descriptor bytes follow it.
	if security == 0 && le.Uint32(metadata[4:]) == 0 {
		security = 8
	}
	if security < 8 || security > uint64(len(metadata)) || le.Uint32(metadata[4:]) != 0 {
		return nil, errors.New("nonempty WIM security table unimplemented")
	}
	rootAt := (security + 7) &^ 7
	root, err := wimRegion(metadata, rootAt, 102)
	if err != nil {
		return nil, err
	}
	rootLength := le.Uint64(root)
	if rootLength < 104 || rootLength > uint64(len(metadata))-rootAt || le.Uint32(root[8:])&0x10 == 0 || le.Uint16(root[96:]) != 0 || le.Uint16(root[98:]) != 0 || le.Uint16(root[100:]) != 0 {
		return nil, errors.New("flat WIM root shape unsupported")
	}
	at := le.Uint64(root[16:])
	if at < rootAt+rootLength || at%8 != 0 {
		return nil, errors.New("WIM child-list offset invalid")
	}
	members := map[string]wimMember{}
	observedReferences := map[string]uint32{}
	ended := false
	for count := 0; count < 4096; count++ {
		prefix, err := wimRegion(metadata, at, 8)
		if err != nil {
			return nil, err
		}
		length := le.Uint64(prefix)
		if length == 0 {
			ended = true
			break
		}
		if length < 104 {
			return nil, errors.New("WIM dentry too short")
		}
		entry, err := wimRegion(metadata, at, length)
		if err != nil {
			return nil, err
		}
		if le.Uint32(entry[8:])&0x410 != 0 || le.Uint64(entry[16:]) != 0 || le.Uint16(entry[96:]) != 0 || le.Uint16(entry[98:]) != 0 {
			return nil, errors.New("WIM nested directory/reparse/alternate streams unsupported")
		}
		nameBytes := uint64(le.Uint16(entry[100:]))
		if nameBytes == 0 || nameBytes%2 != 0 || nameBytes+104 > length {
			return nil, errors.New("WIM filename extent invalid")
		}
		if le.Uint16(entry[102+nameBytes:]) != 0 {
			return nil, errors.New("WIM filename terminator missing")
		}
		name, err := decodeUTF16LE(entry[102 : 102+nameBytes])
		if err != nil {
			return nil, err
		}
		if _, err := model.ValidateRelativePath(name); err != nil {
			return nil, err
		}
		if strings.ContainsAny(name, "/\\") {
			return nil, errors.New("WIM flat member path invalid")
		}
		name = strings.ToLower(name)
		if _, exists := members[name]; exists {
			return nil, errors.New("duplicate WIM member name")
		}
		hash := hex.EncodeToString(entry[64:84])
		data, ok := content[hash]
		if !ok {
			return nil, errors.New("WIM member resource closure missing")
		}
		members[name] = wimMember{data, hash}
		observedReferences[hash]++
		step := (length + 7) &^ 7
		if step < length || step > uint64(len(metadata))-at {
			return nil, errors.New("WIM dentry alignment overflow")
		}
		at += step
	}
	if !ended || len(observedReferences) != len(content) {
		return nil, errors.New("WIM metadata/resource closure incomplete")
	}
	for hash, count := range references {
		if observedReferences[hash] != count {
			return nil, errors.New("WIM resource reference count mismatch")
		}
	}
	return members, nil
}

func decodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("odd UTF16 byte count")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[i*2:])
	}
	for i := 0; i < len(u); i++ {
		v := u[i]
		if v >= 0xd800 && v <= 0xdbff {
			if i+1 == len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", errors.New("unpaired UTF16 surrogate")
			}
			i++
		} else if v >= 0xdc00 && v <= 0xdfff {
			return "", errors.New("unpaired UTF16 surrogate")
		}
	}
	s := string(utf16.Decode(u))
	if !utf8.ValidString(s) {
		return "", errors.New("invalid UTF16 text")
	}
	return strings.TrimPrefix(s, "\ufeff"), nil
}

func sourceManifestSHA256(b []byte, member string) (string, uint64, error) {
	text, err := decodeUTF16LE(b)
	if err != nil {
		return "", 0, err
	}
	section := ""
	digest := ""
	var size uint64
	seenSection := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			if section == "sha256" {
				if seenSection {
					return "", 0, errors.New("duplicate explicit SHA256 manifest section")
				}
				seenSection = true
			}
			continue
		}
		if section != "sha256" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return "", 0, errors.New("malformed explicit SHA256 manifest entry")
		}
		if !strings.EqualFold(name, member) {
			continue
		}
		if digest != "" {
			return "", 0, errors.New("duplicate explicit SHA256 member digest")
		}
		hash, length, ok := strings.Cut(value, ",")
		if !ok {
			return "", 0, errors.New("explicit SHA256 size missing")
		}
		digest = strings.ToLower(hash)
		if err := (model.Digest{Algorithm: model.DigestSHA256, Value: digest}).Validate(); err != nil {
			return "", 0, err
		}
		size, err = strconv.ParseUint(length, 16, 64)
		if err != nil {
			return "", 0, err
		}
	}
	if digest == "" {
		return "", 0, fmt.Errorf("source explicit SHA256 entry missing for requested member")
	}
	return digest, size, nil
}
