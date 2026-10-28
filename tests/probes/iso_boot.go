package probes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

func (r *isoReader) boot(catalog uint32, files map[string]isoFile, e ISOExpectations) (uint16, uint16, error) {
	off := int64(catalog) * isoBlock
	if err := r.isoClaim(off, isoBlock, "El Torito catalog", false); err != nil {
		return 0, 0, err
	}
	p, err := r.read(off, isoBlock)
	if err != nil {
		return 0, 0, err
	}
	var sum uint16
	for i := 0; i < 32; i += 2 {
		sum += le16(p[i:])
	}
	if p[0] != 1 || p[1] != 0xef || p[2] != 0 || p[3] != 0 || p[30] != 0x55 || p[31] != 0xaa || sum != 0 {
		return 0, 0, errors.New("EFI validation entry checksum/magic/platform invalid")
	}
	entry := p[32:64]
	if entry[0] != 0x88 || entry[1] != 0 || le16(entry[2:]) != 0 || entry[4] != 0 || entry[5] != 0 {
		return 0, 0, errors.New("one bootable EFI no-emulation default entry required")
	}
	for _, v := range p[64:] {
		if v != 0 {
			return 0, 0, errors.New("unsupported extra El Torito section/entry")
		}
	}
	var image ISOExpectedFile
	for _, f := range e.Files {
		if f.Path == e.BootImagePath {
			image = f
		}
	}
	load := int64(le16(entry[6:])) * 512
	imageOff := int64(le32(entry[8:])) * isoBlock
	if load <= 0 || load > image.Size || image.Size > 8<<20 || image.Size%512 != 0 {
		return 0, 0, errors.New("EFI load count/image size invalid")
	}
	if err = r.bounds(imageOff, load); err != nil {
		return 0, 0, err
	}
	if err = r.isoClaim(imageOff, image.Size, image.Path, true); err != nil {
		return 0, 0, err
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.NewSectionReader(r.ReaderAt, imageOff, image.Size)); err != nil {
		return 0, 0, err
	}
	if hex.EncodeToString(h.Sum(nil)) != image.SHA256 {
		return 0, 0, errors.New("catalog boot image differs from frozen outer EFI bytes")
	}
	embedded, err := inspectEFIFAT(io.NewSectionReader(r.ReaderAt, imageOff, image.Size), image.Size, e.EmbeddedLoader, e.TargetMachine)
	if err != nil {
		return 0, 0, err
	}
	directFile, ok := files[e.DirectLoaderPath]
	if !ok {
		return 0, 0, errors.New("direct EFI loader missing")
	}
	direct, err := inspectEFIPE(extentReader{r.ReaderAt, directFile}, directFile.size, e.TargetMachine)
	return embedded, direct, err
}

func isoEFIBinding(machine uint16) (path string, magic uint16) {
	switch machine {
	case 0x014c:
		return "EFI/BOOT/BOOTIA32.EFI", 0x010b
	case 0x8664:
		return "EFI/BOOT/BOOTX64.EFI", 0x020b
	case 0xaa64:
		return "EFI/BOOT/BOOTAA64.EFI", 0x020b
	default:
		return "", 0
	}
}

func inspectEFIPE(reader io.ReaderAt, size int64, want uint16) (uint16, error) {
	_, magic := isoEFIBinding(want)
	if reader == nil || size < 256 || magic == 0 {
		return 0, errors.New("short EFI PE")
	}
	head := make([]byte, 64)
	if _, err := reader.ReadAt(head, 0); err != nil {
		return 0, err
	}
	pe := int64(le32(head[60:]))
	if string(head[:2]) != "MZ" || pe < 64 || pe > 1<<20 || pe > size-96 {
		return 0, errors.New("invalid EFI DOS/PE header bounds")
	}
	p := make([]byte, 96)
	if _, err := reader.ReadAt(p, pe); err != nil {
		return 0, err
	}
	machine := le16(p[4:])
	optional := int64(le16(p[20:]))
	if string(p[:4]) != "PE\x00\x00" || machine != want || le16(p[6:]) == 0 || le16(p[6:]) > 96 || optional < 72 || optional > size-pe-24 || le16(p[24:]) != magic || le16(p[92:]) != 10 {
		return 0, errors.New("EFI PE target/optional header/subsystem differs")
	}
	return machine, nil
}

// inspectEFIFAT follows the source EFI image's FAT12/16 directory and file
// chains. It verifies the complete selected loader separately from the direct
// media loader, whose original bytes can legitimately be different.
func inspectEFIFAT(reader io.ReaderAt, size int64, expected ISOExpectedFile, machine uint16) (uint16, error) {
	path, _ := isoEFIBinding(machine)
	if reader == nil || path == "" || size < 4096 || size > 8<<20 || size%512 != 0 || !isoHash(expected.SHA256) || expected.Size <= 0 || expected.Size > size || expected.Path != path {
		return 0, errors.New("bounded source EFI FAT expectations required")
	}
	bpb := make([]byte, 512)
	if _, err := reader.ReadAt(bpb, 0); err != nil {
		return 0, err
	}
	sector := int64(le16(bpb[11:]))
	clusterSectors := int64(bpb[13])
	reserved, fats, roots, fatSectors := int64(le16(bpb[14:])), int64(bpb[16]), int64(le16(bpb[17:])), int64(le16(bpb[22:]))
	total := int64(le16(bpb[19:]))
	if total == 0 {
		total = int64(le32(bpb[32:]))
	}
	if bpb[510] != 0x55 || bpb[511] != 0xaa || sector != 512 || clusterSectors == 0 || clusterSectors > 128 || clusterSectors&(clusterSectors-1) != 0 || reserved == 0 || (fats != 1 && fats != 2) || roots == 0 || roots > 4096 || fatSectors == 0 || total*sector != size {
		return 0, errors.New("unsupported or invalid EFI FAT BPB")
	}
	rootSectors := (roots*32 + sector - 1) / sector
	dataStart := reserved + fats*fatSectors + rootSectors
	if dataStart >= total {
		return 0, errors.New("FAT metadata outside image")
	}
	clusters := (total - dataStart) / clusterSectors
	fat12 := clusters < 4085
	if clusters == 0 || clusters >= 65525 {
		return 0, errors.New("unsupported EFI FAT cluster count")
	}
	fatBytes := fatSectors * sector
	needed := (clusters + 2) * 2
	if fat12 {
		needed = ((clusters+2)*3 + 1) / 2
	}
	if needed > fatBytes || fatBytes > 1<<20 {
		return 0, errors.New("FAT allocation table too small/large")
	}
	read := func(off, n int64) ([]byte, error) {
		if off < 0 || n < 0 || n > 4<<20 || off > size || n > size-off {
			return nil, errors.New("FAT extent outside image")
		}
		p := make([]byte, int(n))
		_, err := reader.ReadAt(p, off)
		return p, err
	}
	fat, err := read(reserved*sector, fatBytes)
	if err != nil {
		return 0, err
	}
	if fat[0] != bpb[21] || fat[1] != 0xff || fat[2] != 0xff {
		return 0, errors.New("invalid FAT reserved/media entries")
	}
	if fats == 2 {
		other, err := read((reserved+fatSectors)*sector, fatBytes)
		if err != nil {
			return 0, err
		}
		if !bytes.Equal(fat, other) {
			return 0, errors.New("EFI FAT copies differ")
		}
	}
	used := map[uint32]bool{}
	clusterBytes := clusterSectors * sector
	chain := func(first uint32) ([]isoExtent, error) {
		var out []isoExtent
		current := first
		for len(out) <= int(clusters) {
			if current < 2 || int64(current) >= clusters+2 || used[current] {
				return nil, errors.New("invalid, crosslinked or cyclic FAT chain")
			}
			used[current] = true
			out = append(out, isoExtent{(dataStart + (int64(current)-2)*clusterSectors) * sector, clusterBytes})
			var next uint32
			if fat12 {
				at := int(current + current/2)
				if at+1 >= len(fat) {
					return nil, errors.New("FAT12 entry outside table")
				}
				next = uint32(le16(fat[at:]))
				if current&1 != 0 {
					next >>= 4
				} else {
					next &= 0xfff
				}
				if next >= 0xff8 {
					return out, nil
				}
			} else {
				at := int(current) * 2
				if at+1 >= len(fat) {
					return nil, errors.New("FAT16 entry outside table")
				}
				next = uint32(le16(fat[at:]))
				if next >= 0xfff8 {
					return out, nil
				}
			}
			current = next
		}
		return nil, errors.New("FAT chain count bound")
	}
	dir, err := read((reserved+fats*fatSectors)*sector, roots*32)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(expected.Path, "/")
	for index, name := range parts {
		target := name
		if strings.Contains(name, ".") {
			x := strings.Split(name, ".")
			if len(x) != 2 || len(x[0]) > 8 || len(x[1]) > 3 {
				return 0, errors.New("unsupported FAT target name")
			}
			target = x[0] + strings.Repeat(" ", 8-len(x[0])) + x[1] + strings.Repeat(" ", 3-len(x[1]))
		} else {
			target = name + strings.Repeat(" ", 11-len(name))
		}
		var entry []byte
		for at := 0; at+32 <= len(dir); at += 32 {
			p := dir[at : at+32]
			if p[0] == 0 {
				break
			}
			if p[0] == 0xe5 || p[11] == 0x0f || p[11]&8 != 0 {
				continue
			}
			if string(p[:11]) == target {
				if entry != nil {
					return 0, errors.New("duplicate FAT boot path")
				}
				entry = append([]byte(nil), p...)
			}
		}
		if entry == nil || le16(entry[20:]) != 0 || entry[11]&0xc0 != 0 {
			return 0, errors.New("EFI FAT boot path missing/invalid")
		}
		isDir := entry[11]&0x10 != 0
		if isDir != (index < len(parts)-1) {
			return 0, errors.New("EFI FAT boot path type differs")
		}
		extents, err := chain(uint32(le16(entry[26:])))
		if err != nil {
			return 0, err
		}
		capacity := int64(len(extents)) * clusterBytes
		if isDir {
			if capacity > 4<<20 {
				return 0, errors.New("EFI FAT directory bound")
			}
			dir = make([]byte, int(capacity))
			if _, err = (extentReader{reader, isoFile{capacity, extents}}).ReadAt(dir, 0); err != nil {
				return 0, err
			}
			continue
		}
		length := int64(le32(entry[28:]))
		if length != expected.Size || length > capacity || capacity-length >= clusterBytes {
			return 0, errors.New("FAT loader size/allocation differs")
		}
		file := isoFile{length, extents}
		h := sha256.New()
		if _, err = io.Copy(h, io.NewSectionReader(extentReader{reader, file}, 0, length)); err != nil {
			return 0, err
		}
		if hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
			return 0, errors.New("embedded EFI loader differs from original expected bytes")
		}
		return inspectEFIPE(extentReader{reader, file}, length, machine)
	}
	return 0, errors.New("embedded EFI loader absent")
}
