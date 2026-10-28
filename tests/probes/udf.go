package probes

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// This reader intentionally supports UDF 1.02 with one type-1 physical
// partition only. Virtual, sparable, metadata, indirect and sparse allocations
// are explicit errors rather than guessed or silently mounted fallbacks.
type udfLayout struct {
	start, blocks                            uint32
	number                                   uint16
	fsd, fsdBytes, integrity, integrityBytes uint32
	lvd                                      []byte
}

func udfCRC(p []byte) uint16 {
	var c uint16
	for _, v := range p {
		c ^= uint16(v) << 8
		for i := 0; i < 8; i++ {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
	}
	return c
}
func udfTag(p []byte, id uint16, loc uint32, minimum int) error {
	if len(p) < 16 || le16(p) != id || le16(p[2:]) != 2 || p[5] != 0 || le32(p[12:]) != loc {
		return errors.New("invalid UDF tag identity/version/location")
	}
	var sum byte
	for i, v := range p[:16] {
		if i != 4 {
			sum += v
		}
	}
	if sum != p[4] {
		return errors.New("invalid UDF tag checksum")
	}
	n := int(le16(p[10:]))
	if n < minimum || n > len(p)-16 || udfCRC(p[16:16+n]) != le16(p[8:]) {
		return errors.New("invalid UDF descriptor CRC/length")
	}
	return nil
}
func udfDomain(p []byte) bool {
	return len(p) >= 32 && strings.TrimRight(string(p[1:24]), "\x00") == "*OSTA UDF Compliant" && le16(p[24:]) == 0x102
}
func udfString(p []byte) (string, error) {
	if len(p) < 2 {
		return "", errors.New("short UDF dstring")
	}
	n := int(p[len(p)-1])
	if n == 0 {
		return "", nil
	}
	if n > len(p)-1 {
		return "", errors.New("invalid UDF dstring length")
	}
	return udfName(p[:n])
}
func udfName(p []byte) (string, error) {
	if len(p) == 0 {
		return "", errors.New("empty UDF name")
	}
	var b strings.Builder
	switch p[0] {
	case 8:
		for _, v := range p[1:] {
			if v < 0x20 || v > 0x7e {
				return "", errors.New("unsupported UDF character")
			}
			b.WriteByte(v)
		}
	case 16:
		if len(p)%2 != 1 {
			return "", errors.New("invalid UDF 16-bit name")
		}
		for at := 1; at < len(p); at += 2 {
			v := binary.BigEndian.Uint16(p[at:])
			if v < 0x20 || v > 0x7e {
				return "", errors.New("unsupported UDF character")
			}
			b.WriteByte(byte(v))
		}
	default:
		return "", errors.New("unsupported UDF name compression")
	}
	return b.String(), nil
}
func (r *isoReader) udf(volume string) (map[string]isoFile, error) {
	state := 0
	for n := int64(16); n < 80; n++ {
		p, err := r.read(n*isoBlock, isoBlock)
		if err != nil {
			return nil, err
		}
		id := string(p[1:6])
		if id == "BEA01" || id == "NSR02" || id == "NSR03" || id == "TEA01" {
			want := []string{"BEA01", "NSR02", "TEA01"}
			if state >= 3 || id != want[state] || p[0] != 0 || p[6] != 1 {
				return nil, errors.New("UDF 1.02 volume recognition sequence required")
			}
			if err := r.claim(n*isoBlock, isoBlock, "UDF recognition", false); err != nil {
				return nil, err
			}
			state++
			if state == 3 {
				break
			}
		}
	}
	if state != 3 {
		return nil, errors.New("UDF recognition sequence absent")
	}
	anchor, err := r.read(256*isoBlock, isoBlock)
	if err != nil {
		return nil, err
	}
	if err = udfAnchor(anchor, 256, anchor); err != nil {
		return nil, err
	}
	if err = r.claim(256*isoBlock, isoBlock, "UDF anchor", false); err != nil {
		return nil, err
	}
	mainBytes, main := le32(anchor[16:]), le32(anchor[20:])
	reserveBytes, reserve := le32(anchor[24:]), le32(anchor[28:])
	if mainBytes == 0 || reserveBytes == 0 || mainBytes%2048 != 0 || reserveBytes%2048 != 0 || mainBytes > 128*2048 || reserveBytes > 128*2048 {
		return nil, errors.New("unsupported volume descriptor sequence length")
	}
	backup := 0
	anchors := []int64{256 * isoBlock}
	for _, n := range []int64{r.size/isoBlock - 257, r.size/isoBlock - 1} {
		if n == 256 {
			continue
		}
		p, err := r.read(n*isoBlock, isoBlock)
		if err != nil {
			return nil, err
		}
		if le16(p) != 2 {
			continue
		}
		if err = udfAnchor(p, uint32(n), anchor); err != nil {
			return nil, err
		}
		if err = r.claim(n*isoBlock, isoBlock, "UDF backup anchor", false); err != nil {
			return nil, err
		}
		anchors = append(anchors, n*isoBlock)
		backup++
	}
	if backup == 0 || (r.isoSize < r.size && backup != 2) {
		return nil, errors.New("UDF backup anchor missing")
	}
	a, ac, err := r.udfSequence(main, mainBytes, volume, nil)
	if err != nil {
		return nil, err
	}
	b, bc, err := r.udfSequence(reserve, reserveBytes, volume, anchor)
	if err != nil {
		return nil, err
	}
	if a.start != b.start || a.blocks != b.blocks || a.number != b.number || a.fsd != b.fsd || a.fsdBytes != b.fsdBytes || a.integrity != b.integrity || a.integrityBytes != b.integrityBytes || len(ac) != len(bc) {
		return nil, errors.New("main/reserve layouts disagree")
	}
	for id, p := range ac {
		if !bytes.Equal(p, bc[id]) {
			return nil, errors.New("main/reserve descriptor content differs")
		}
	}
	fileCount, directoryCount, err := r.udfIntegrity(a)
	if err != nil {
		return nil, err
	}
	fsdOff, err := a.offset(a.fsd, a.fsdBytes)
	if err != nil {
		return nil, err
	}
	if a.fsdBytes > 64*2048 || a.fsdBytes%2048 != 0 {
		return nil, errors.New("unsupported file set sequence extent")
	}
	var root, rootBytes uint32
	found, ended := false, false
	for at := uint32(0); at < a.fsdBytes; at += 2048 {
		p, err := r.read(fsdOff+int64(at), isoBlock)
		if err != nil {
			return nil, err
		}
		id := le16(p)
		if id != 256 && id != 8 {
			return nil, errors.New("unsupported file set descriptor")
		}
		if err = udfTag(p, id, a.fsd+at/2048, 496); err != nil {
			return nil, err
		}
		if err = r.claim(fsdOff+int64(at), isoBlock, "UDF file set", false); err != nil {
			return nil, err
		}
		if id == 8 {
			ended = true
			break
		}
		if found || !udfDomain(p[416:448]) || le32(p[448:]) != 0 {
			return nil, errors.New("unsupported file set domain or continuation")
		}
		label, err := udfString(p[112:240])
		if err != nil || label != volume {
			return nil, errors.New("file set volume label differs")
		}
		root, rootBytes, err = udfLongAD(p[400:416])
		if err != nil {
			return nil, err
		}
		// This producer's ICBs each occupy one complete logical block.
		if rootBytes != uint32(isoBlock) {
			return nil, errors.New("unsupported root ICB extent length")
		}
		found = true
	}
	if !found || !ended {
		return nil, errors.New("file set/root or terminator missing")
	}
	files := map[string]isoFile{}
	seen := map[uint32]bool{}
	var walk func(uint32, string, uint32, int) error
	walk = func(lba uint32, path string, parent uint32, depth int) error {
		if depth > 16 || len(seen) >= 1024 || seen[lba] {
			return errors.New("cyclic or oversized UDF directory/ICB graph")
		}
		seen[lba] = true
		f, dir, err := r.udfEntry(a, lba, path)
		if err != nil {
			return err
		}
		if !dir {
			if path == "" || len(files) >= 512 {
				return errors.New("invalid UDF file count")
			}
			files[path] = f
			return nil
		}
		if f.size == 0 || f.size > 4<<20 {
			return errors.New("UDF directory size bound")
		}
		buf := make([]byte, int(f.size))
		if _, err = (extentReader{r.ReaderAt, f}).ReadAt(buf, 0); err != nil {
			return err
		}
		local := map[string]bool{}
		parents := 0
		for at := 0; at < len(buf); {
			if len(buf)-at < 38 {
				return errors.New("short UDF file identifier")
			}
			p := buf[at:]
			nameLen, impl := int(p[19]), int(le16(p[36:]))
			n := (38 + impl + nameLen + 3) &^ 3
			if n > len(p) || impl%4 != 0 || n > 2048 {
				return errors.New("UDF file identifier bounds")
			}
			logicalOffset, err := udfFileLocation(f, int64(at), a.start)
			if err != nil {
				return err
			}
			if err = udfTag(p[:n], 257, logicalOffset, n-16); err != nil {
				return err
			}
			if le16(p[16:]) != 1 || p[18]&^byte(0x0a) != 0 {
				return errors.New("unsupported UDF identifier flags/version")
			}
			target, targetBytes, err := udfLongAD(p[20:36])
			if err != nil {
				return err
			}
			if targetBytes != uint32(isoBlock) {
				return errors.New("unsupported FID ICB extent length")
			}
			if p[18]&8 != 0 {
				if p[18]&2 == 0 || nameLen != 0 || target != parent || parents != 0 {
					return errors.New("UDF parent identifier differs")
				}
				parents++
				at += n
				continue
			}
			name, err := udfName(p[38+impl : 38+impl+nameLen])
			if err != nil || !isoPath(name) || strings.Contains(name, "/") || local[name] {
				return errors.New("invalid/duplicate UDF file name")
			}
			local[name] = true
			child := name
			if path != "" {
				child = path + "/" + name
			}
			entry, err := a.offset(target, 2048)
			if err != nil {
				return err
			}
			header, err := r.read(entry, 36)
			if err != nil {
				return err
			}
			if (header[27] == 4) != (p[18]&2 != 0) {
				return errors.New("UDF identifier/ICB directory type differs")
			}
			if err = walk(target, child, lba, depth+1); err != nil {
				return err
			}
			at += n
		}
		if parents != 1 {
			return errors.New("UDF parent identifier missing")
		}
		return nil
	}
	if err = walk(root, "", root, 0); err != nil {
		return nil, err
	}
	if uint32(len(files)) != fileCount || uint32(len(seen)-len(files)) != directoryCount {
		return nil, errors.New("UDF integrity file/directory counts differ from reconstructed graph")
	}
	if err = r.udfTail(int64(reserve)*isoBlock, int64(reserveBytes), anchors, anchor); err != nil {
		return nil, err
	}
	return files, nil
}

func udfZero(p []byte) bool {
	for _, v := range p {
		if v != 0 {
			return false
		}
	}
	return true
}
func udfAnchor(p []byte, location uint32, reference []byte) error {
	if err := udfTag(p, 2, location, 496); err != nil {
		return err
	}
	if le16(p[10:]) != 496 || !udfZero(p[32:]) || len(reference) < 32 || !bytes.Equal(p[16:32], reference[16:32]) {
		return errors.New("UDF anchor pointers/body/padding differ")
	}
	return nil
}

func (r *isoReader) udfTail(reserveOff, reserveBytes int64, anchors []int64, reference []byte) error {
	if r.isoSize == r.size {
		return nil
	}
	if reserveOff < r.isoSize {
		return errors.New("unsupported UDF reserve tail placement")
	}
	for off := r.isoSize; off < r.size; {
		if off >= reserveOff && off < reserveOff+reserveBytes {
			off = reserveOff + reserveBytes
			continue
		}
		anchor := false
		for _, a := range anchors {
			if off == a {
				anchor = true
				break
			}
		}
		if anchor {
			off += isoBlock
			continue
		}
		p, err := r.read(off, isoBlock)
		if err != nil {
			return err
		}
		if !udfZero(p) {
			if err = udfAnchor(p, uint32(off/isoBlock), reference); err != nil {
				return fmt.Errorf("uncovered UDF tail block: %w", err)
			}
			if err = r.claim(off, isoBlock, "UDF redundant tail anchor", false); err != nil {
				return err
			}
		}
		off += isoBlock
	}
	return nil
}
func (r *isoReader) udfSequence(lba, n uint32, volume string, anchor []byte) (udfLayout, map[uint16][]byte, error) {
	var a udfLayout
	content := map[uint16][]byte{}
	off := int64(lba) * isoBlock
	if err := r.claim(off, int64(n), "UDF volume descriptor sequence", false); err != nil {
		return a, nil, err
	}
	ended := false
	for at := uint32(0); at < n; at += 2048 {
		p, err := r.read(off+int64(at), isoBlock)
		if err != nil {
			return a, nil, err
		}
		id := le16(p)
		minimum := 496
		if id == 6 {
			minimum = 430
		}
		if id == 7 {
			minimum = 8
		}
		if err = udfTag(p, id, lba+at/2048, minimum); err != nil {
			return a, nil, err
		}
		if content[id] != nil {
			return a, nil, errors.New("duplicate UDF volume descriptor")
		}
		content[id] = append([]byte(nil), p[16:16+int(le16(p[10:]))]...)
		switch id {
		case 1, 4, 7:
		case 5:
			if le16(p[20:]) != 1 || strings.TrimRight(string(p[25:48]), "\x00") != "+NSR02" || le32(p[184:]) != 1 {
				return a, nil, errors.New("unsupported physical partition descriptor")
			}
			a.number = le16(p[22:])
			a.start = le32(p[188:])
			a.blocks = le32(p[192:])
			if a.blocks == 0 || r.bounds(int64(a.start)*isoBlock, int64(a.blocks)*isoBlock) != nil {
				return a, nil, errors.New("partition outside image")
			}
		case 6:
			label, err := udfString(p[84:212])
			if err != nil || label != volume || le32(p[212:]) != 2048 || !udfDomain(p[216:248]) || le32(p[264:]) != 6 || le32(p[268:]) != 1 || p[440] != 1 || p[441] != 6 || le16(p[442:]) != 1 {
				return a, nil, errors.New("unsupported UDF volume/revision/type-1 partition map")
			}
			a.lvd = append([]byte(nil), p...)
			a.fsd, a.fsdBytes, err = udfLongAD(p[248:264])
			if err != nil {
				return a, nil, err
			}
			a.integrityBytes = le32(p[432:])
			a.integrity = le32(p[436:])
		case 8:
			ended = true
		default:
			return a, nil, fmt.Errorf("unsupported UDF volume descriptor %d", id)
		}
		if ended {
			for rest := at + 2048; rest < n; rest += 2048 {
				padding, err := r.read(off+int64(rest), isoBlock)
				if err != nil {
					return a, nil, err
				}
				if !udfZero(padding) {
					if anchor == nil {
						return a, nil, errors.New("nonzero UDF main-sequence padding")
					}
					if err = udfAnchor(padding, lba+rest/2048, anchor); err != nil {
						return a, nil, fmt.Errorf("invalid UDF reserve anchor: %w", err)
					}
				}
			}
			break
		}
	}
	if !ended || content[1] == nil || content[5] == nil || content[6] == nil || a.lvd == nil || le16(a.lvd[444:]) != a.number {
		return a, nil, errors.New("UDF primary/partition/logical-volume/terminator missing or misbound")
	}
	return a, content, nil
}
func udfLongAD(p []byte) (uint32, uint32, error) {
	if len(p) < 16 || le32(p)&0xc0000000 != 0 || le32(p) == 0 || le16(p[8:]) != 0 {
		return 0, 0, errors.New("unsupported/empty UDF long allocation descriptor")
	}
	return le32(p[4:]), le32(p), nil
}
func (a udfLayout) offset(lba, n uint32) (int64, error) {
	if lba >= a.blocks || uint64(n) > uint64(a.blocks-lba)*2048 {
		return 0, errors.New("UDF allocation outside physical partition")
	}
	return (int64(a.start) + int64(lba)) * isoBlock, nil
}
func (r *isoReader) udfIntegrity(a udfLayout) (uint32, uint32, error) {
	if a.integrityBytes == 0 || a.integrityBytes > 64*2048 || a.integrityBytes%2048 != 0 {
		return 0, 0, errors.New("unsupported UDF integrity sequence")
	}
	off := int64(a.integrity) * isoBlock
	if err := r.claim(off, int64(a.integrityBytes), "UDF integrity sequence", false); err != nil {
		return 0, 0, err
	}
	p, err := r.read(off, isoBlock)
	if err != nil {
		return 0, 0, err
	}
	if err = udfTag(p, 9, a.integrity, 72); err != nil {
		return 0, 0, err
	}
	n, impl := le32(p[72:]), le32(p[76:])
	if le32(p[28:]) != 1 || le32(p[32:]) != 0 || n != 1 || impl < 46 || uint64(80)+uint64(n)*8+uint64(impl) > uint64(16+le16(p[10:])) || le32(p[84:]) != a.blocks {
		return 0, 0, errors.New("invalid/unclosed UDF integrity descriptor")
	}
	at := int(80 + n*8)
	if le16(p[at+40:]) != 0x102 || le16(p[at+42:]) != 0x102 || le16(p[at+44:]) != 0x102 {
		return 0, 0, errors.New("UDF integrity revision differs")
	}
	if !udfZero(p[16+int(le16(p[10:])):]) {
		return 0, 0, errors.New("nonzero UDF integrity block padding")
	}
	terminated := false
	for offset := uint32(2048); offset < a.integrityBytes; offset += 2048 {
		tail, err := r.read(off+int64(offset), isoBlock)
		if err != nil {
			return 0, 0, err
		}
		if udfZero(tail) {
			terminated = true
			continue
		}
		if terminated || le16(tail) != 8 {
			return 0, 0, errors.New("unsupported trailing UDF integrity record")
		}
		if err = udfTag(tail, 8, a.integrity+offset/2048, 496); err != nil {
			return 0, 0, err
		}
		if !udfZero(tail[16:]) {
			return 0, 0, errors.New("nonzero UDF integrity terminator padding")
		}
		terminated = true
	}
	return le32(p[at+32:]), le32(p[at+36:]), nil
}
func (r *isoReader) udfEntry(a udfLayout, lba uint32, path string) (isoFile, bool, error) {
	var f isoFile
	off, err := a.offset(lba, 2048)
	if err != nil {
		return f, false, err
	}
	p, err := r.read(off, isoBlock)
	if err != nil {
		return f, false, err
	}
	if err = udfTag(p, 261, lba, 160); err != nil {
		return f, false, err
	}
	if le16(p[20:]) != 4 || (p[27] != 4 && p[27] != 5) || le32(p[112:]) != 0 {
		return f, false, errors.New("unsupported UDF ICB strategy/type/extended-attribute ICB")
	}
	dir := p[27] == 4
	if err = r.claim(off, isoBlock, "UDF entry "+path, false); err != nil {
		return f, false, err
	}
	length := binary.LittleEndian.Uint64(p[56:])
	ea, ad := uint64(le32(p[168:])), uint64(le32(p[172:]))
	if length > uint64(isoLimit) || 176+ea+ad > 2048 || 176+ea+ad > uint64(16+le16(p[10:])) || ea%4 != 0 {
		return f, false, errors.New("UDF entry/allocation length bound")
	}
	f.size = int64(length)
	mode := le16(p[34:]) & 7
	alloc := p[176+ea : 176+ea+ad]
	if mode == 3 {
		if ad != length {
			return f, false, errors.New("embedded UDF content length differs")
		}
		f.extents = []isoExtent{{off + int64(176+ea), int64(ad)}}
		return f, dir, nil
	}
	width := 8
	if mode == 1 {
		width = 16
	} else if mode != 0 {
		return f, false, errors.New("unsupported UDF allocation descriptor mode")
	}
	if len(alloc)%width != 0 || len(alloc)/width > 256 {
		return f, false, errors.New("UDF allocation descriptor count/alignment")
	}
	var total int64
	for at := 0; at < len(alloc); at += width {
		q := alloc[at:]
		n, block := le32(q), le32(q[4:])
		if n == 0 || n&0xc0000000 != 0 || mode == 1 && le16(q[8:]) != 0 {
			return f, false, errors.New("unsupported sparse/continuation/foreign UDF allocation")
		}
		position, err := a.offset(block, n)
		if err != nil {
			return f, false, err
		}
		if at+width < len(alloc) && n%2048 != 0 {
			return f, false, errors.New("interior UDF allocation must be block aligned")
		}
		name, data := "UDF directory "+path, false
		if !dir {
			name = path
			data = true
		}
		if err = r.claim(position, int64(n), name, data); err != nil {
			return f, false, err
		}
		f.extents = append(f.extents, isoExtent{position, int64(n)})
		total += int64(n)
	}
	if total < f.size || total-f.size >= 2048 || f.size == 0 && total != 0 {
		return f, false, errors.New("UDF allocated/information length differs")
	}
	return f, dir, nil
}
func udfFileLocation(f isoFile, offset int64, start uint32) (uint32, error) {
	for _, x := range f.extents {
		if offset < x.size {
			pos := x.offset + offset
			if pos/isoBlock < int64(start) {
				return 0, errors.New("UDF directory outside partition")
			}
			return uint32(pos/isoBlock - int64(start)), nil
		}
		offset -= x.size
	}
	return 0, io.ErrUnexpectedEOF
}
