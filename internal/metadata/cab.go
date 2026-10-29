package metadata

import (
	"context"
	"encoding/binary"
	"sort"
	"strings"

	"uupbuilder/internal/model"
)

const MaxMetadataCABBytes = 32 << 20

type CABMember struct {
	Name                 string
	Size, Offset, Folder int
}
type CABInventory struct {
	CabinetBytes, TrailingBytes, DecodedBytes int
	Members                                   []CABMember
}
type cabSpan struct{ start, end int }

// InspectCAB validates the entire directory and compressed table spans before
// allowing any extraction. Trailing bytes are opaque, not authenticated seals.
// Split cabinets, paths and special/device names are deliberately unsupported.
func InspectCAB(ctx context.Context, b []byte) (CABInventory, error) {
	var out CABInventory
	if ctx == nil {
		return out, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if len(b) > MaxMetadataCABBytes {
		return out, ErrLimit
	}
	if len(b) < 36 || string(b[:4]) != "MSCF" {
		return out, ErrMalformedMetadata
	}
	u16 := func(n int) int { return int(binary.LittleEndian.Uint16(b[n:])) }
	u32 := func(n int) int64 { return int64(binary.LittleEndian.Uint32(b[n:])) }
	size64 := u32(8)
	if size64 < 36 || size64 > int64(len(b)) {
		return out, ErrMalformedMetadata
	}
	size := int(size64)
	if u32(4) != 0 || u32(12) != 0 || u32(20) != 0 || b[24] != 3 || b[25] != 1 || u16(30)&^4 != 0 {
		return out, ErrMalformedMetadata
	}
	folders, files := u16(26), u16(28)
	if folders == 0 || files == 0 || folders > 1024 || files > 1024 {
		return out, ErrLimit
	}
	pos, resFolder, resData := 36, 0, 0
	if u16(30)&4 != 0 {
		if pos+4 > size {
			return out, ErrMalformedMetadata
		}
		reserved := u16(pos)
		resFolder = int(b[pos+2])
		resData = int(b[pos+3])
		pos += 4 + reserved
	}
	if pos > size || folders > (size-pos)/(8+resFolder) {
		return out, ErrMalformedMetadata
	}
	folderEnd := pos + folders*(8+resFolder)
	filePos64 := u32(16)
	if filePos64 < int64(folderEnd) || filePos64 >= int64(size) {
		return out, ErrMalformedMetadata
	}
	filePos := int(filePos64)
	folderSizes := make([]int, folders)
	var spans []cabSpan
	for i := 0; i < folders; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		p := pos + i*(8+resFolder)
		block64 := u32(p)
		blocks := u16(p + 4)
		compression := u16(p + 6)
		if blocks == 0 || block64 < int64(folderEnd) || block64 >= int64(size) || compression&15 > 3 {
			return out, ErrMalformedMetadata
		}
		block := int(block64)
		start := block
		for j := 0; j < blocks; j++ {
			if block > size-8-resData {
				return out, ErrMalformedMetadata
			}
			compressed, decoded := u16(block+4), u16(block+6)
			if decoded == 0 || decoded > 32768 || compressed == 0 || compressed > size-block-8-resData {
				return out, ErrMalformedMetadata
			}
			if compression&15 == 0 && compressed != decoded {
				return out, ErrMalformedMetadata
			}
			folderSizes[i] += decoded
			if folderSizes[i] > 128<<20 {
				return out, ErrLimit
			}
			block += 8 + resData + compressed
		}
		spans = append(spans, cabSpan{start, block})
	}
	totalFolders := 0
	for _, n := range folderSizes {
		totalFolders += n
		if totalFolders > 128<<20 {
			return out, ErrLimit
		}
	}
	seen := map[string]bool{}
	ranges := make([][]cabSpan, folders)
	for i := 0; i < files; i++ {
		if filePos > size-17 {
			return out, ErrMalformedMetadata
		}
		memberSize64, offset64 := u32(filePos), u32(filePos+4)
		folder := u16(filePos + 8)
		if memberSize64 > 16<<20 {
			return out, ErrLimit
		}
		if folder >= folders || offset64+memberSize64 > int64(folderSizes[folder]) {
			return out, ErrMalformedMetadata
		}
		nameStart := filePos + 16
		end := nameStart
		for end < size && b[end] != 0 && end-nameStart <= 255 {
			end++
		}
		if end == size || end-nameStart > 255 {
			return out, ErrMalformedMetadata
		}
		name := string(b[nameStart:end])
		filePos = end + 1
		normalized, err := model.ValidateRelativePath(name)
		if err != nil || normalized != name || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || name == "" || seen[strings.ToLower(name)] {
			return out, ErrMalformedMetadata
		}
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return out, ErrMalformedMetadata
			}
		}
		seen[strings.ToLower(name)] = true
		m := CABMember{Name: name, Size: int(memberSize64), Offset: int(offset64), Folder: folder}
		out.Members = append(out.Members, m)
		out.DecodedBytes += m.Size
		if out.DecodedBytes > 128<<20 {
			return out, ErrLimit
		}
		ranges[folder] = append(ranges[folder], cabSpan{m.Offset, m.Offset + m.Size})
	}
	spans = append(spans, cabSpan{0, filePos})
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return out, ErrMalformedMetadata
		}
	}
	for _, rr := range ranges {
		sort.Slice(rr, func(i, j int) bool { return rr[i].start < rr[j].start })
		for i := 1; i < len(rr); i++ {
			if rr[i].start < rr[i-1].end {
				return out, ErrMalformedMetadata
			}
		}
	}
	out.CabinetBytes = size
	out.TrailingBytes = len(b) - size
	return out, nil
}
