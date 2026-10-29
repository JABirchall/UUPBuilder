package wimindex

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"

	"uupbuilder/internal/model"
)

var disk = binary.LittleEndian

const zeroSHA1 = "0000000000000000000000000000000000000000"
const solidMarker = uint64(0x100000000)

// wimlib v1.14.5 src/wim.c wim_ctype_info: validate declarations without
// allocating a chunk or asserting that any codec is available.
func validCodecChunk(chunk, compression uint32) bool {
	if chunk == 0 || chunk&(chunk-1) != 0 {
		return false
	}
	switch compression {
	case 1:
		return chunk >= 4096 && chunk <= 65536
	case 2:
		return chunk >= 32768 && chunk <= 2097152
	case 3:
		return chunk >= 32768 && chunk <= 1073741824
	}
	return false
}

func descriptor(b []byte) Descriptor {
	return Descriptor{Size: disk.Uint64(b) & 0x00ffffffffffffff, Flags: b[7], Offset: disk.Uint64(b[8:]), Original: disk.Uint64(b[16:])}
}
func extent(d Descriptor, size uint64) error {
	if d.Size == 0 {
		if d != (Descriptor{}) {
			return ErrLayout
		}
		return nil
	}
	if d.Offset < 208 || d.Offset > size || d.Size > size-d.Offset {
		return ErrLayout
	}
	return nil
}
func readRange(ctx context.Context, r io.ReaderAt, size, offset uint64, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if offset > size || uint64(len(b)) > size-offset || offset > math.MaxInt64 {
		return ErrLayout
	}
	n, err := r.ReadAt(b, int64(offset))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || n != len(b) {
		return ErrLayout
	}
	return nil
}

type interval struct {
	start, size uint64
	hash        string
	descriptor  Descriptor
}

func validateIntervals(regions []interval) error {
	slices.SortFunc(regions, func(a, b interval) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		if a.size < b.size {
			return -1
		}
		if a.size > b.size {
			return 1
		}
		return 0
	})
	var previous interval
	for i, v := range regions {
		if i != 0 && v.start < previous.start+previous.size {
			// Repeated descriptors for the same blob or backing solid resource are
			// aliases. A partial overlap or different content identity is illegal.
			if v.start != previous.start || v.size != previous.size || v.hash != previous.hash || v.descriptor != previous.descriptor {
				return ErrConflict
			}
		}
		previous = v
	}
	return nil
}

// Layout references are pinned to wimlib v1.14.5 header.h/resource.h and
// blob_table.c read_blob_table, assign_blob_to_solid_resource. This is an
// independent bounded reader of the documented structures; no wimlib is loaded.
func readContainer(ctx context.Context, r io.ReaderAt, size uint64, p model.PayloadIdentity, l Limits, remaining int) (Container, []Gap, error) {
	c := Container{Payload: p}
	var gaps []Gap
	add := func(entry uint32, why string) { gaps = append(gaps, gap(p, entry, why)) }
	var raw [208]byte
	if err := readRange(ctx, r, size, 0, raw[:]); err != nil {
		return c, nil, err
	}
	pipable := string(raw[:8]) == "WLPWM\x00\x00\x00"
	if (!pipable && string(raw[:8]) != "MSWIM\x00\x00\x00") || disk.Uint32(raw[8:]) != 208 {
		return c, nil, ErrLayout
	}
	c.Header = Header{Version: disk.Uint32(raw[12:]), Flags: disk.Uint32(raw[16:]), ChunkSize: disk.Uint32(raw[20:]), GUID: hex.EncodeToString(raw[24:40]), Part: disk.Uint16(raw[40:]), TotalParts: disk.Uint16(raw[42:]), ImageCount: disk.Uint32(raw[44:]), BootIndex: disk.Uint32(raw[120:]), Lookup: descriptor(raw[48:72]), XML: descriptor(raw[72:96]), Boot: descriptor(raw[96:120]), Integrity: descriptor(raw[124:148])}
	h := c.Header
	if pipable {
		add(0, "pipable-header")
		return c, gaps, nil
	}
	if h.Version != 0xe00 && h.Version != 0x10d00 {
		add(0, "header-version")
		return c, gaps, nil
	}
	if h.Part == 0 || h.TotalParts == 0 || h.Part > h.TotalParts || h.BootIndex > h.ImageCount {
		return c, nil, ErrLayout
	}
	if h.ImageCount > 65535 {
		return c, nil, ErrLimit
	}
	if h.TotalParts != 1 || h.Part != 1 || h.Flags&8 != 0 {
		add(0, "split-parts")
		return c, gaps, nil
	}
	if h.Flags&0x40 != 0 {
		add(0, "write-in-progress")
		return c, gaps, nil
	}
	if h.Flags & ^uint32(0xe00bf) != 0 {
		add(0, "header-flags")
		return c, gaps, nil
	}
	compression := h.Flags & 0xe0000
	if h.Flags&2 != 0 {
		if compression == 0 || compression&(compression-1) != 0 || h.ChunkSize == 0 || h.ChunkSize > 1<<30 || h.ChunkSize&(h.ChunkSize-1) != 0 {
			return c, nil, ErrLayout
		}
		ctype := compression >> 17
		if ctype == 4 {
			ctype = 3
		}
		if !validCodecChunk(h.ChunkSize, ctype) {
			return c, nil, ErrLayout
		}
		if compression == 0x80000 && h.Version != 0xe00 {
			add(0, "LZMS-header-version")
			return c, gaps, nil
		}
	} else if compression != 0 || h.ChunkSize != 0 {
		return c, nil, ErrLayout
	}
	regions := []interval{{start: 0, size: 208, hash: "header"}}
	for i, d := range []Descriptor{h.Lookup, h.XML, h.Integrity, h.Boot} {
		if err := extent(d, size); err != nil {
			return c, nil, err
		}
		if d.Size != 0 && i != 3 {
			regions = append(regions, interval{d.Offset, d.Size, fmt.Sprint("header-resource-", i), d})
		}
	}
	if err := validateIntervals(slices.Clone(regions)); err != nil {
		return c, nil, err
	}
	if h.Lookup.Size == 0 {
		add(0, "missing-lookup-table")
		return c, gaps, nil
	}
	if h.Lookup.Original%50 != 0 {
		return c, nil, ErrLayout
	}
	count := h.Lookup.Original / 50
	if count > uint64(l.MaxEntries) || count > uint64(remaining) {
		return c, nil, ErrLimit
	}
	if h.Lookup.Flags != 0 && h.Lookup.Flags != 2 {
		add(0, "lookup-table-encoding")
		return c, gaps, nil
	}
	if h.Lookup.Size != h.Lookup.Original {
		return c, nil, ErrLayout
	}
	// 1000 records per read bounds temporary allocation independently of the
	// declared table. Retained records are limited above before allocation.
	c.Entries = make([]Entry, 0, int(count))
	var batch [50000]byte
	for pos := uint64(0); pos < count; {
		n := min(uint64(1000), count-pos)
		b := batch[:n*50]
		if err := readRange(ctx, r, size, h.Lookup.Offset+pos*50, b); err != nil {
			return c, nil, err
		}
		for j := uint64(0); j < n; j++ {
			v := b[j*50 : (j+1)*50]
			d := descriptor(v)
			e := Entry{Ordinal: uint32(pos + j + 1), Descriptor: d, Part: disk.Uint16(v[24:]), References: disk.Uint32(v[26:]), SHA1: hex.EncodeToString(v[30:50]), Kind: "unresolved"}
			c.Entries = append(c.Entries, e)
		}
		pos += n
	}
	for at := 0; at < len(c.Entries); {
		if err := ctx.Err(); err != nil {
			return c, nil, err
		}
		e := &c.Entries[at]
		d := e.Descriptor
		if d.Flags&16 != 0 {
			if h.Version != 0xe00 {
				add(e.Ordinal, "solid-version")
				at++
				continue
			}
			end := at + 1
			for end < len(c.Entries) && c.Entries[end].Descriptor.Flags&16 != 0 {
				end++
			}
			more, err := resolveSolid(ctx, r, size, c.Entries[at:end], p, &regions)
			if err != nil {
				return c, nil, err
			}
			gaps = append(gaps, more...)
			at = end
			continue
		}
		if e.Part != h.Part {
			add(e.Ordinal, "cross-part-resource")
			at++
			continue
		}
		if d.Flags & ^byte(0x16) != 0 {
			add(e.Ordinal, "resource-flags")
			at++
			continue
		}
		if err := extent(d, size); err != nil {
			return c, nil, err
		}
		if d.Size == 0 || d.Original == 0 || (d.Flags&4 == 0 && d.Size != d.Original) || (d.Flags&4 != 0 && h.Flags&2 == 0) {
			return c, nil, ErrLayout
		}
		effectiveCompression := uint32(0)
		if d.Flags&4 != 0 {
			switch compression {
			case 0x20000:
				effectiveCompression = 1
			case 0x40000:
				effectiveCompression = 2
			case 0x80000:
				effectiveCompression = 3
			}
		}
		e.Kind = "ordinary"
		if d.Flags&2 != 0 {
			e.Kind = "metadata"
		}
		e.LogicalSize = d.Original
		e.Located = true
		e.Location = Location{ResourceEntry: e.Ordinal, PhysicalOffset: d.Offset, PhysicalSize: d.Size, ResourceLogicalSize: d.Original, Compression: effectiveCompression}
		if effectiveCompression != 0 {
			e.Location.ChunkSize = h.ChunkSize
		}
		// ResourceEntry is an ordinal, not physical identity: shared references
		// compare the original descriptor and hash in validateIntervals.
		regions = append(regions, interval{d.Offset, d.Size, e.SHA1, d})
		at++
	}
	if err := validateIntervals(regions); err != nil {
		return c, nil, err
	}
	// BootMetadata aliases a metadata entry, and must not be counted twice as a
	// physical resource. Only table order defines the per-image index.
	mappingSafe := true
	var mapped []int
	for i := range c.Entries {
		e := &c.Entries[i]
		if e.Descriptor.Flags&2 == 0 {
			continue
		}
		if e.References == 0 {
			continue
		}
		if !e.Located || e.Kind != "metadata" || e.References != 1 || e.SHA1 == zeroSHA1 {
			add(e.Ordinal, "metadata-image-association")
			mappingSafe = false
			continue
		}
		mapped = append(mapped, i)
	}
	if len(mapped) != int(h.ImageCount) {
		add(0, "metadata-image-count")
		mappingSafe = false
	}
	if mappingSafe {
		for i, entry := range mapped {
			c.Entries[entry].ImageIndex = uint32(i + 1)
		}
	}
	if h.BootIndex == 0 {
		if h.Boot != (Descriptor{}) {
			return c, nil, ErrConflict
		}
	} else if mappingSafe {
		if c.Entries[mapped[h.BootIndex-1]].Descriptor != h.Boot {
			return c, nil, ErrConflict
		}
	} else {
		add(0, "boot-metadata-association")
	}
	images, xmlGaps, err := readImages(ctx, r, size, c, l)
	if err != nil {
		return c, nil, err
	}
	gaps = append(gaps, xmlGaps...)
	if len(xmlGaps) != 0 {
		mappingSafe = false
	}
	if mappingSafe {
		for i := range images {
			images[i].MetadataEntry = c.Entries[mapped[images[i].Index-1]].Ordinal
		}
	}
	c.Images = images
	c.MappingComplete = mappingSafe
	return c, gaps, nil
}

func resolveSolid(ctx context.Context, r io.ReaderAt, size uint64, entries []Entry, p model.PayloadIdentity, regions *[]interval) ([]Gap, error) {
	var gaps []Gap
	var resources []int
	var starts []uint64
	var total uint64
	for i := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e := &entries[i]
		d := e.Descriptor
		if e.Part != 1 || d.Flags != 16 {
			gaps = append(gaps, gap(p, e.Ordinal, "solid-resource-flags-or-part"))
			return gaps, nil
		}
		if d.Original != solidMarker {
			continue
		}
		if err := extent(d, size); err != nil {
			return nil, err
		}
		if d.Size < 16 {
			return nil, ErrLayout
		}
		var b [16]byte
		if err := readRange(ctx, r, size, d.Offset, b[:]); err != nil {
			return nil, err
		}
		usize := disk.Uint64(b[:])
		chunk, compression := disk.Uint32(b[8:]), disk.Uint32(b[12:])
		if usize == 0 || chunk == 0 || chunk > 1<<30 || chunk&(chunk-1) != 0 || total > math.MaxUint64-usize {
			return nil, ErrLayout
		}
		if compression >= 1 && compression <= 3 && !validCodecChunk(chunk, compression) {
			return nil, ErrLayout
		}
		if compression > 3 {
			gaps = append(gaps, gap(p, e.Ordinal, "solid-compression-format"))
		}
		starts = append(starts, total)
		total += usize
		resources = append(resources, i)
		e.Kind = "solid-resource"
		e.Located = true
		e.LogicalSize = usize
		e.Location = Location{ResourceEntry: e.Ordinal, PhysicalOffset: d.Offset, PhysicalSize: d.Size, ResourceLogicalSize: usize, ChunkSize: chunk, Compression: compression}
		*regions = append(*regions, interval{d.Offset, d.Size, "solid-resource", d})
	}
	if len(resources) == 0 {
		return nil, ErrLayout
	}
	logical := map[uint32][]interval{}
	for i := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e := &entries[i]
		d := e.Descriptor
		if d.Original == solidMarker {
			continue
		}
		if d.Size == 0 || d.Offset > math.MaxUint64-d.Size {
			return nil, ErrLayout
		}
		// Search the concatenated logical resource address space; do not read at
		// d.Offset, which is never a physical file offset for a solid blob.
		at := sort.Search(len(resources), func(j int) bool {
			return d.Offset < starts[j]+entries[resources[j]].LogicalSize
		})
		if at == len(resources) || d.Offset < starts[at] {
			return nil, ErrLayout
		}
		backing := entries[resources[at]]
		offset := d.Offset - starts[at]
		if offset > backing.LogicalSize || d.Size > backing.LogicalSize-offset {
			return nil, ErrLayout
		}
		e.Kind = "solid-blob"
		e.LogicalSize = d.Size
		e.Located = true
		e.Location = backing.Location
		e.Location.LogicalOffset = offset
		// Alias ordinals must resolve to the same physical resource, so the extent
		// identity here contains only the logical blob facts, not its table ordinal.
		logical[backing.Ordinal] = append(logical[backing.Ordinal], interval{offset, d.Size, e.SHA1, Descriptor{Size: d.Size, Offset: offset}})
	}
	for _, ranges := range logical {
		if err := validateIntervals(ranges); err != nil {
			return nil, err
		}
	}
	return gaps, nil
}
