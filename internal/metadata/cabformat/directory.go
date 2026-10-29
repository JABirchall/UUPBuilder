// Package cabformat validates bounded cabinet framing without decompression.
package cabformat

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"

	"uupbuilder/internal/model"
)

var ErrLayout = errors.New("malformed cabinet framing")
var ErrLimit = errors.New("cabinet framing limit exceeded")
var ErrUnsupported = errors.New("unsupported cabinet layout")

// Zero limits select ceilings; nonzero limits can only lower them. MetadataBytes
// counts actual bounded ReaderAt bytes, independently of the source/output caps.
type Limits struct {
	MaxSourceBytes, MaxMemberBytes, MaxDecodedBytes, MaxMetadataBytes, MaxDirectoryBytes uint64
	MaxFolders, MaxMembers, MaxBlocks, MaxNameBytes                                      int
	FlatASCII                                                                            bool
}
type Member struct {
	Name         string
	Size, Offset uint64
	Folder       int
	Attributes   uint16
}
type Inventory struct {
	CabinetBytes, TrailingBytes, DecodedBytes, FolderBytes, MetadataBytes uint64
	Members                                                               []Member
	Compressions                                                          []uint16
	Blocks                                                                int
}
type span struct{ start, end uint64 }

func Bounds(l Limits) (Limits, error) {
	for i, p := range []*uint64{&l.MaxSourceBytes, &l.MaxMemberBytes, &l.MaxDecodedBytes, &l.MaxMetadataBytes, &l.MaxDirectoryBytes} {
		c := []uint64{1 << 30, 256 << 20, 2 << 30, 32 << 20, 128 << 20}[i]
		if *p > c {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = c
		}
	}
	for i, p := range []*int{&l.MaxFolders, &l.MaxMembers, &l.MaxBlocks, &l.MaxNameBytes} {
		c := []int{4096, 65535, 4194304, 255}[i]
		if *p < 0 || *p > c {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = c
		}
	}
	return l, nil
}
func Inspect(ctx context.Context, r io.ReaderAt, size uint64, l Limits) (out Inventory, err error) {
	if ctx == nil || r == nil {
		return out, ErrLayout
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	l, err = Bounds(l)
	if err != nil {
		return out, err
	}
	if size > l.MaxSourceBytes {
		return out, ErrLimit
	}
	if size < 36 {
		return out, ErrLayout
	}
	read := func(b []byte, off uint64) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if off > size || uint64(len(b)) > size-off {
			return ErrLayout
		}
		if uint64(len(b)) > l.MaxMetadataBytes-out.MetadataBytes {
			return ErrLimit
		}
		out.MetadataBytes += uint64(len(b))
		n, e := r.ReadAt(b, int64(off))
		if e != nil || n != len(b) {
			return errors.Join(ErrLayout, e)
		}
		return nil
	}
	var h [36]byte
	if err = read(h[:], 0); err != nil {
		return out, err
	}
	u16 := binary.LittleEndian.Uint16
	u32 := binary.LittleEndian.Uint32
	cab := uint64(u32(h[8:]))
	if string(h[:4]) != "MSCF" || cab < 36 || cab > size || u32(h[4:]) != 0 || u32(h[12:]) != 0 || u32(h[20:]) != 0 || h[24] != 3 || h[25] != 1 {
		return out, ErrLayout
	}
	flags := u16(h[30:])
	if flags&^uint16(7) != 0 {
		return out, ErrLayout
	}
	if flags&3 != 0 || u16(h[34:]) != 0 && !l.FlatASCII {
		return out, ErrUnsupported
	}
	folders, files := int(u16(h[26:])), int(u16(h[28:]))
	if folders == 0 || files == 0 || folders > l.MaxFolders || files > l.MaxMembers {
		return out, ErrLimit
	}
	pos := uint64(36)
	rf, rd := uint64(0), uint64(0)
	if flags&4 != 0 {
		var b [4]byte
		if err = read(b[:], pos); err != nil {
			return out, err
		}
		pos += 4 + uint64(u16(b[:]))
		rf, rd = uint64(b[2]), uint64(b[3])
	}
	if pos > cab || uint64(folders) > (cab-pos)/(8+rf) {
		return out, ErrLayout
	}
	folderEnd := pos + uint64(folders)*(8+rf)
	filePos := uint64(u32(h[16:]))
	if filePos < folderEnd || filePos >= cab {
		return out, ErrLayout
	}
	if uint64(folders)*8+uint64(files)*17 > l.MaxMetadataBytes-out.MetadataBytes {
		return out, ErrLimit
	}
	if uint64(files)*1024+uint64(folders)*256 > l.MaxDirectoryBytes {
		return out, ErrLimit
	}
	// Counts have passed hard caps before these bounded directory allocations.
	sizes := make([]uint64, folders)
	ranges := make([][]span, folders)
	spans := make([]span, 0, folders+1)
	out.Compressions = make([]uint16, 0, folders)
	blocksTotal := 0
	for i := 0; i < folders; i++ {
		var b [8]byte
		if err = read(b[:], pos+uint64(i)*(8+rf)); err != nil {
			return out, err
		}
		block := uint64(u32(b[:]))
		blocks := int(u16(b[4:]))
		compression := u16(b[6:])
		if blocks == 0 || block < folderEnd || block >= cab || compression&15 > 3 {
			return out, ErrLayout
		}
		if blocks > l.MaxBlocks-blocksTotal {
			return out, ErrLimit
		}
		blocksTotal += blocks
		out.Blocks = blocksTotal
		start := block
		for j := 0; j < blocks; j++ {
			if block > cab || 8+rd > cab-block {
				return out, ErrLayout
			}
			var d [8]byte
			if err = read(d[:], block); err != nil {
				return out, err
			}
			compressed, decoded := uint64(u16(d[4:])), uint64(u16(d[6:]))
			if decoded == 0 || decoded > 32768 || compressed == 0 || compressed > cab-block-8-rd || compression&15 == 0 && compressed != decoded {
				return out, ErrLayout
			}
			if decoded > l.MaxDecodedBytes-out.FolderBytes {
				return out, ErrLimit
			}
			out.FolderBytes += decoded
			sizes[i] += decoded
			block += 8 + rd + compressed
		}
		spans = append(spans, span{start, block})
		out.Compressions = append(out.Compressions, compression)
	}
	seen := make(map[string]bool, files)
	for i := 0; i < files; i++ {
		if filePos > cab || 17 > cab-filePos {
			return out, ErrLayout
		}
		var b [16]byte
		if err = read(b[:], filePos); err != nil {
			return out, err
		}
		m := Member{Size: uint64(u32(b[:])), Offset: uint64(u32(b[4:])), Folder: int(u16(b[8:])), Attributes: u16(b[14:])}
		if m.Size > l.MaxMemberBytes || m.Size > l.MaxDecodedBytes-out.DecodedBytes {
			return out, ErrLimit
		}
		if m.Folder >= 0xfffd {
			return out, ErrUnsupported
		}
		if m.Folder >= folders || m.Offset > sizes[m.Folder] || m.Size > sizes[m.Folder]-m.Offset {
			return out, ErrLayout
		}
		filePos += 16
		var name [256]byte
		nn := 0
		for {
			if filePos >= cab {
				return out, ErrLayout
			}
			if err = read(name[nn:nn+1], filePos); err != nil {
				return out, err
			}
			filePos++
			if name[nn] == 0 {
				break
			}
			nn++
			if nn > l.MaxNameBytes {
				if l.MaxNameBytes == 255 && l.FlatASCII {
					return out, ErrLayout
				}
				return out, ErrLimit
			}
		}
		m.Name = string(name[:nn])
		normalized, e := model.ValidateRelativePath(m.Name)
		if e != nil {
			return out, ErrLayout
		}
		key := strings.ToLower(normalized)
		if seen[key] {
			return out, ErrLayout
		}
		seen[key] = true
		if l.FlatASCII {
			if normalized != m.Name || strings.ContainsAny(m.Name, "/\\") || strings.Contains(m.Name, "..") {
				return out, ErrLayout
			}
			for _, r := range m.Name {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
					return out, ErrLayout
				}
			}
		}
		out.DecodedBytes += m.Size
		out.Members = append(out.Members, m)
		ranges[m.Folder] = append(ranges[m.Folder], span{m.Offset, m.Offset + m.Size})
	}
	spans = append(spans, span{0, filePos})
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return out, ErrLayout
		}
	}
	for _, rr := range ranges {
		sort.Slice(rr, func(i, j int) bool { return rr[i].start < rr[j].start })
		for i := 1; i < len(rr); i++ {
			if rr[i].start < rr[i-1].end {
				return out, ErrLayout
			}
		}
	}
	out.CabinetBytes = cab
	out.TrailingBytes = size - cab
	return out, ctx.Err()
}
