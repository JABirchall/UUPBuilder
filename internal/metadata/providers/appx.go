package providers

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type Appx struct{}

// Appx observes a single package manifest. Bundle expansion and blockmap/signature
// validation are separate missing operations; XML observations cannot authorize
// provisioning or establish licenses, package selection or installability.
func (Appx) Inspect(ctx context.Context, r metadata.LocalResource, limits metadata.Limits) (metadata.ProviderResult, error) {
	var out metadata.ProviderResult
	limit, err := documentLimit(limits)
	if err != nil {
		return out, err
	}
	f, err := verified(ctx, r)
	if err != nil {
		return out, err
	}
	defer f.Close()
	z, err := newAppxZIP(ctx, f, r.Identity.Size)
	if err != nil {
		return out, err
	}
	if len(z.File) > 4096 {
		return out, metadata.ErrLimit
	}
	seen := map[string]bool{}
	var manifest *zip.File
	for _, entry := range z.File {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		name := strings.TrimSuffix(entry.Name, "/")
		normal, err := model.ValidateRelativePath(name)
		key := strings.ToLower(name)
		if err != nil || normal != name || seen[key] || (!entry.Mode().IsRegular() && !entry.FileInfo().IsDir()) {
			return out, metadata.ErrMalformedMetadata
		}
		seen[key] = true
		if key == "appxmetadata/appxbundlemanifest.xml" {
			return out, ErrUnsupported
		}
		if key == "appxmanifest.xml" {
			if !entry.Mode().IsRegular() {
				return out, metadata.ErrMalformedMetadata
			}
			manifest = entry
		}
	}
	if manifest == nil {
		return out, metadata.ErrMalformedMetadata
	}
	if manifest.UncompressedSize64 > uint64(limit) {
		return out, metadata.ErrLimit
	}
	reader, err := manifest.Open()
	if err != nil {
		return out, metadata.ErrMalformedMetadata
	}
	body, readErr := io.ReadAll(contextReader{ctx, io.LimitReader(reader, limit+1)})
	closeErr := reader.Close()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if readErr != nil || closeErr != nil || uint64(len(body)) != manifest.UncompressedSize64 {
		return out, metadata.ErrIntegrity
	}
	if int64(len(body)) > limit {
		return out, metadata.ErrLimit
	}
	out.Documents = []metadata.MetadataDocument{{Resource: metadata.ResourceReference{Payload: r.Identity, Member: manifest.Name}, Format: metadata.FormatAppxXML, Original: body, Provenance: "uupbuilder:appx-zip-manifest-v1"}}
	return out, nil
}

const (
	maxAppxDirectoryBytes   = 8 << 20
	maxAppxDirectoryEntries = 4096
)

// ReadAt observes cancellation during archive/zip setup as well as content
// reads. The validated directory/trailer is a bounded immutable snapshot, so
// later source writes cannot change the record count seen by archive/zip.
type appxZIPReaderAt struct {
	ctx        context.Context
	source     io.ReaderAt
	tailOffset int64
	tail       []byte
}

func (r appxZIPReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, metadata.ErrMalformedMetadata
	}
	n := 0
	if r.tail != nil && off >= r.tailOffset {
		n, e := bytes.NewReader(r.tail).ReadAt(p, off-r.tailOffset)
		if err := r.ctx.Err(); err != nil {
			return n, err
		}
		return n, e
	}
	first := len(p)
	if r.tail != nil && int64(first) > r.tailOffset-off {
		first = int(r.tailOffset - off)
	}
	var err error
	n, err = r.source.ReadAt(p[:first], off)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	if err != nil || n != first || first == len(p) {
		return n, err
	}
	m, err := bytes.NewReader(r.tail).ReadAt(p[n:], 0)
	return n + m, err
}

// Preflight the actual central records before archive/zip can allocate File
// objects. Constants/layout follow Go's archive/zip EOCD/ZIP64 directory reader;
// Appx requires a contiguous single-disk directory with no SFX/base-offset fixup.
func newAppxZIP(ctx context.Context, r io.ReaderAt, size int64) (*zip.Reader, error) {
	if ctx == nil || r == nil {
		return nil, metadata.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if size < 22 {
		return nil, metadata.ErrMalformedMetadata
	}
	reader := appxZIPReaderAt{ctx: ctx, source: r}
	endBytes := make([]byte, int(min(size, 65535+22)))
	if _, err := reader.ReadAt(endBytes, size-int64(len(endBytes))); err != nil {
		return nil, err
	}
	end := -1
	for i := len(endBytes) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(endBytes[i:]) == 0x06054b50 {
			end = i
			break
		}
	}
	if end < 0 || end+22+int(binary.LittleEndian.Uint16(endBytes[end+20:])) != len(endBytes) {
		return nil, metadata.ErrMalformedMetadata
	}
	e := endBytes[end:]
	if binary.LittleEndian.Uint16(e[4:]) != 0 || binary.LittleEndian.Uint16(e[6:]) != 0 || binary.LittleEndian.Uint16(e[8:]) != binary.LittleEndian.Uint16(e[10:]) {
		return nil, metadata.ErrMalformedMetadata
	}
	count := uint64(binary.LittleEndian.Uint16(e[10:]))
	directorySize := uint64(binary.LittleEndian.Uint32(e[12:]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(e[16:]))
	endOffset := size - int64(len(endBytes)) + int64(end)
	if count == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff {
		if endOffset < 20 {
			return nil, metadata.ErrMalformedMetadata
		}
		var locator [20]byte
		if _, err := reader.ReadAt(locator[:], endOffset-20); err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(locator[:]) != 0x07064b50 || binary.LittleEndian.Uint32(locator[4:]) != 0 || binary.LittleEndian.Uint32(locator[16:]) != 1 {
			return nil, metadata.ErrMalformedMetadata
		}
		offset := binary.LittleEndian.Uint64(locator[8:])
		if offset > uint64(endOffset-20) || uint64(endOffset-20)-offset < 56 {
			return nil, metadata.ErrMalformedMetadata
		}
		var z64 [56]byte
		if _, err := reader.ReadAt(z64[:], int64(offset)); err != nil {
			return nil, err
		}
		length := binary.LittleEndian.Uint64(z64[4:])
		if length > 65535 {
			return nil, metadata.ErrLimit
		}
		if binary.LittleEndian.Uint32(z64[:]) != 0x06064b50 || length < 44 || offset+12+length != uint64(endOffset-20) || binary.LittleEndian.Uint32(z64[16:]) != 0 || binary.LittleEndian.Uint32(z64[20:]) != 0 || binary.LittleEndian.Uint64(z64[24:]) != binary.LittleEndian.Uint64(z64[32:]) {
			return nil, metadata.ErrMalformedMetadata
		}
		count = binary.LittleEndian.Uint64(z64[32:])
		directorySize = binary.LittleEndian.Uint64(z64[40:])
		directoryOffset = binary.LittleEndian.Uint64(z64[48:])
		endOffset = int64(offset)
	}
	if directorySize > maxAppxDirectoryBytes || count > maxAppxDirectoryEntries {
		return nil, metadata.ErrLimit
	}
	if directoryOffset > uint64(endOffset) || directorySize != uint64(endOffset)-directoryOffset {
		return nil, metadata.ErrMalformedMetadata
	}
	// At most the directory, one bounded ZIP64 trailer and the EOCD/comment.
	tailSize := size - int64(directoryOffset)
	if tailSize > maxAppxDirectoryBytes+2*65535+98 {
		return nil, metadata.ErrLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tail := make([]byte, int(tailSize))
	if _, err := reader.ReadAt(tail, int64(directoryOffset)); err != nil {
		return nil, err
	}
	var at uint64
	actual := uint64(0)
	for at < directorySize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if actual >= maxAppxDirectoryEntries {
			return nil, metadata.ErrLimit
		}
		if directorySize-at < 46 {
			return nil, metadata.ErrMalformedMetadata
		}
		h := tail[at : at+46]
		if binary.LittleEndian.Uint32(h) != 0x02014b50 {
			return nil, metadata.ErrMalformedMetadata
		}
		entrySize := uint64(46) + uint64(binary.LittleEndian.Uint16(h[28:])) + uint64(binary.LittleEndian.Uint16(h[30:])) + uint64(binary.LittleEndian.Uint16(h[32:]))
		if entrySize > directorySize-at {
			return nil, metadata.ErrMalformedMetadata
		}
		at += entrySize
		actual++
	}
	if actual != count {
		return nil, metadata.ErrMalformedMetadata
	}
	reader.tailOffset, reader.tail = int64(directoryOffset), tail
	z, err := zip.NewReader(reader, size)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, metadata.ErrMalformedMetadata
	}
	return z, nil
}
