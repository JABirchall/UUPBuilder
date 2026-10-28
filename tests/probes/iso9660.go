package probes

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const isoBlock int64 = 2048
const isoLimit int64 = 5 << 30

// These probe-local DTOs bind content to pre-mastering inputs, not the
// nondeterministic outer ISO digest. No gate schema or trust flag is involved.
type ISOExpectedFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type ISOExpectations struct {
	Volume           string            `json:"volume"`
	Files            []ISOExpectedFile `json:"files"`
	TargetMachine    uint16            `json:"target_machine"`
	DirectLoaderPath string            `json:"direct_loader_path"`
	BootImagePath    string            `json:"boot_image_path"`
	EmbeddedLoader   ISOExpectedFile   `json:"embedded_loader"`
}
type ISOInspection struct {
	Size            int64             `json:"size"`
	SHA256          string            `json:"sha256"`
	ISOFiles        []ISOExpectedFile `json:"iso9660_files"`
	UDFFiles        []ISOExpectedFile `json:"udf_files"`
	EmbeddedMachine uint16            `json:"embedded_machine"`
	DirectMachine   uint16            `json:"direct_machine"`
}
type isoExtent struct{ offset, size int64 }
type isoFile struct {
	size    int64
	extents []isoExtent
}
type isoClaim struct {
	start, end int64
	name       string
	data       bool
}
type isoReader struct {
	io.ReaderAt
	size    int64
	isoSize int64
	claims  []isoClaim
}

func (r *isoReader) isoClaim(off, n int64, name string, data bool) error {
	rounded := (n + isoBlock - 1) / isoBlock * isoBlock
	if r.isoSize <= 0 || off < 0 || n < 0 || off > r.isoSize || rounded > r.isoSize-off {
		return errors.New("extent outside ISO declared volume")
	}
	return r.claim(off, n, name, data)
}

func (r *isoReader) bounds(off, n int64) error {
	if off < 0 || n < 0 || off > r.size || n > r.size-off {
		return errors.New("ISO extent outside image")
	}
	return nil
}
func (r *isoReader) read(off, n int64) ([]byte, error) {
	if n > 4<<20 {
		return nil, errors.New("structural read exceeds 4 MiB bound")
	}
	if err := r.bounds(off, n); err != nil {
		return nil, err
	}
	p := make([]byte, int(n))
	_, err := r.ReadAt(p, off)
	return p, err
}
func (r *isoReader) claim(off, n int64, name string, data bool) error {
	if n == 0 {
		return nil
	}
	n = (n + isoBlock - 1) / isoBlock * isoBlock
	if err := r.bounds(off, n); err != nil {
		return err
	}
	for _, x := range r.claims {
		if off < x.end && x.start < off+n {
			if data && x.data && x.name == name && x.start == off && x.end == off+n {
				return nil
			}
			return fmt.Errorf("overlapping ISO allocations: %s and %s", name, x.name)
		}
	}
	if len(r.claims) >= 8192 {
		return errors.New("ISO allocation count bound exceeded")
	}
	r.claims = append(r.claims, isoClaim{off, off + n, name, data})
	return nil
}

// InspectISO parses the closed, single-session ISO9660/UDF1.02 bridge and one
// EFI no-emulation entry. Every payload is streamed separately through both
// namespaces. It neither mounts the image nor executes any contained bytes.
func InspectISO(reader io.ReaderAt, size int64, expected ISOExpectations) (ISOInspection, error) {
	var result ISOInspection
	if reader == nil || size < 600*isoBlock || size > isoLimit || size%isoBlock != 0 {
		return result, errors.New("bounded aligned ISO length required")
	}
	want, err := validateISOExpectations(expected)
	if err != nil {
		return result, err
	}
	r := &isoReader{ReaderAt: reader, size: size}
	files, catalog, err := r.iso9660(expected.Volume)
	if err != nil {
		return result, fmt.Errorf("ISO9660: %w", err)
	}
	result.ISOFiles, err = r.verifyFiles(files, want)
	if err != nil {
		return result, fmt.Errorf("ISO9660: %w", err)
	}
	udfFiles, err := r.udf(expected.Volume)
	if err != nil {
		return result, fmt.Errorf("UDF: %w", err)
	}
	result.UDFFiles, err = r.verifyFiles(udfFiles, want)
	if err != nil {
		return result, fmt.Errorf("UDF: %w", err)
	}
	result.EmbeddedMachine, result.DirectMachine, err = r.boot(catalog, files, expected)
	if err != nil {
		return result, fmt.Errorf("El Torito/EFI: %w", err)
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.NewSectionReader(reader, 0, size)); err != nil {
		return result, err
	}
	result.Size = size
	result.SHA256 = hex.EncodeToString(h.Sum(nil))
	return result, nil
}
func validateISOExpectations(e ISOExpectations) (map[string]ISOExpectedFile, error) {
	loaderPath, _ := isoEFIBinding(e.TargetMachine)
	if e.Volume == "" || len(e.Volume) > 32 || len(e.Files) == 0 || len(e.Files) > 512 || loaderPath == "" {
		return nil, errors.New("closed x86/amd64/ARM64 ISO expectations required")
	}
	w := map[string]ISOExpectedFile{}
	for _, f := range e.Files {
		if !isoPath(f.Path) || f.Size <= 0 || f.Size > 0xffffffff || !isoHash(f.SHA256) || w[f.Path].Path != "" {
			return nil, errors.New("invalid or duplicate ISO content expectation")
		}
		w[f.Path] = f
	}
	if e.DirectLoaderPath != loaderPath || w[e.DirectLoaderPath].Path == "" || w[e.BootImagePath].Path == "" || e.EmbeddedLoader.Path != loaderPath || e.EmbeddedLoader.Size <= 0 || e.EmbeddedLoader.Size > 8<<20 || !isoHash(e.EmbeddedLoader.SHA256) {
		return nil, errors.New("source-bound target EFI boot roles required")
	}
	return w, nil
}
func isoHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}
func isoPath(s string) bool {
	if s == "" || len(s) > 256 || strings.HasPrefix(s, "/") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 31 {
			return false
		}
		for _, c := range part {
			if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}
func dual16(p []byte) (uint16, error) {
	a := binary.LittleEndian.Uint16(p)
	if a != binary.BigEndian.Uint16(p[2:]) {
		return 0, errors.New("dual-endian uint16 mismatch")
	}
	return a, nil
}
func dual32(p []byte) (uint32, error) {
	a := binary.LittleEndian.Uint32(p)
	if a != binary.BigEndian.Uint32(p[4:]) {
		return 0, errors.New("dual-endian uint32 mismatch")
	}
	return a, nil
}
func le32(p []byte) uint32 { return binary.LittleEndian.Uint32(p) }
func le16(p []byte) uint16 { return binary.LittleEndian.Uint16(p) }

// extentReader projects potentially fragmented UDF allocations as a ReaderAt.
// File sizes and allocation arithmetic were bounded before this is constructed.
type extentReader struct {
	source io.ReaderAt
	file   isoFile
}

func (r extentReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.file.size {
		return 0, io.EOF
	}
	total := 0
	remaining := r.file.size - off
	for _, x := range r.file.extents {
		if off >= x.size {
			off -= x.size
			continue
		}
		n := int64(len(p) - total)
		if n > x.size-off {
			n = x.size - off
		}
		if n > remaining {
			n = remaining
		}
		got, err := r.source.ReadAt(p[total:total+int(n)], x.offset+off)
		total += got
		remaining -= int64(got)
		if err != nil {
			return total, err
		}
		off = 0
		if total == len(p) {
			return total, nil
		}
		if remaining == 0 {
			return total, io.EOF
		}
	}
	return total, io.EOF
}

func (r *isoReader) verifyFiles(files map[string]isoFile, want map[string]ISOExpectedFile) ([]ISOExpectedFile, error) {
	if len(files) != len(want) {
		return nil, errors.New("namespace file count differs from frozen source bindings")
	}
	names := make([]string, 0, len(want))
	for p := range want {
		names = append(names, p)
	}
	sort.Strings(names)
	out := make([]ISOExpectedFile, 0, len(names))
	for _, name := range names {
		f, ok := files[name]
		w := want[name]
		if !ok || f.size != w.Size {
			return nil, fmt.Errorf("missing or wrong-size file %s", name)
		}
		h := sha256.New()
		n, err := io.Copy(h, io.NewSectionReader(extentReader{r.ReaderAt, f}, 0, f.size))
		if err != nil {
			return nil, err
		}
		digest := hex.EncodeToString(h.Sum(nil))
		if n != w.Size || digest != w.SHA256 {
			return nil, fmt.Errorf("file content differs from pre-run source %s", name)
		}
		out = append(out, ISOExpectedFile{name, n, digest})
	}
	return out, nil
}

type isoDir struct {
	path      string
	lba, size uint32
	parent    uint32
}

func (r *isoReader) iso9660(volume string) (map[string]isoFile, uint32, error) {
	var pvd []byte
	var catalog uint32
	terminated := false
	for n := int64(16); n < 80; n++ {
		p, err := r.read(n*isoBlock, isoBlock)
		if err != nil {
			return nil, 0, err
		}
		if string(p[1:6]) != "CD001" || p[6] != 1 {
			return nil, 0, errors.New("invalid volume descriptor identifier/version")
		}
		if err = r.claim(n*isoBlock, isoBlock, "ISO descriptor", false); err != nil {
			return nil, 0, err
		}
		switch p[0] {
		case 0:
			if catalog != 0 || strings.TrimRight(string(p[7:39]), "\x00 ") != "EL TORITO SPECIFICATION" {
				return nil, 0, errors.New("one El Torito boot descriptor required")
			}
			catalog = le32(p[71:])
		case 1:
			if pvd != nil {
				return nil, 0, errors.New("duplicate primary volume")
			}
			pvd = p
		case 255:
			terminated = true
		default:
			return nil, 0, errors.New("unsupported ISO descriptor")
		}
		if terminated {
			break
		}
	}
	if !terminated || pvd == nil || catalog == 0 {
		return nil, 0, errors.New("primary/terminating/boot descriptor missing")
	}
	blocks, err := dual32(pvd[80:])
	if err != nil || blocks == 0 || int64(blocks)*isoBlock > r.size {
		return nil, 0, errors.New("volume space size/endian mismatch")
	}
	r.isoSize = int64(blocks) * isoBlock
	for _, claim := range r.claims {
		if claim.end > r.isoSize {
			return nil, 0, errors.New("descriptor outside ISO declared volume")
		}
	}
	for _, off := range []int{120, 124} {
		v, e := dual16(pvd[off:])
		if e != nil || v != 1 {
			return nil, 0, errors.New("unsupported volume set/sequence")
		}
	}
	block, err := dual16(pvd[128:])
	if err != nil || block != 2048 {
		return nil, 0, errors.New("unsupported logical block size")
	}
	if strings.TrimRight(string(pvd[40:72]), " ") != volume {
		return nil, 0, errors.New("volume label mismatch")
	}
	root, err := isoRecord(pvd[156:])
	if err != nil || root.name != "\x00" || !root.dir {
		return nil, 0, errors.New("invalid root directory record")
	}
	files := map[string]isoFile{}
	dirs := []isoDir{{"", root.lba, root.size, root.lba}}
	seen := map[uint32]bool{}
	for at := 0; at < len(dirs); at++ {
		d := dirs[at]
		if len(dirs) > 256 || seen[d.lba] || strings.Count(d.path, "/") > 16 || d.size == 0 || d.size > 4<<20 {
			return nil, 0, errors.New("invalid, cyclic or oversized ISO directory")
		}
		seen[d.lba] = true
		if err := r.isoClaim(int64(d.lba)*isoBlock, int64(d.size), "ISO directory "+d.path, false); err != nil {
			return nil, 0, err
		}
		allocated := (int64(d.size) + isoBlock - 1) / isoBlock * isoBlock
		buf, err := r.read(int64(d.lba)*isoBlock, allocated)
		if err != nil {
			return nil, 0, err
		}
		for _, padding := range buf[d.size:] {
			if padding != 0 {
				return nil, 0, errors.New("nonzero ISO directory allocation padding")
			}
		}
		buf = buf[:d.size]
		local := map[string]bool{}
		dots := 0
		for pos := 0; pos < len(buf); {
			if buf[pos] == 0 {
				end := (pos/2048 + 1) * 2048
				if end > len(buf) {
					end = len(buf)
				}
				for _, v := range buf[pos:end] {
					if v != 0 {
						return nil, 0, errors.New("nonzero directory padding")
					}
				}
				pos = end
				continue
			}
			n := int(buf[pos])
			if n > len(buf)-pos || pos%2048+n > 2048 {
				return nil, 0, errors.New("directory record crosses block or extent")
			}
			rec, err := isoRecord(buf[pos : pos+n])
			if err != nil {
				return nil, 0, err
			}
			pos += n
			if rec.name == "\x00" || rec.name == "\x01" {
				want := d.lba
				wantSize := d.size
				if rec.name == "\x01" {
					want = d.parent
					for _, parent := range dirs {
						if parent.lba == d.parent {
							wantSize = parent.size
							break
						}
					}
				}
				if !rec.dir || rec.lba != want || rec.size != wantSize || local[rec.name] {
					return nil, 0, errors.New("invalid self/parent directory")
				}
				local[rec.name] = true
				dots++
				continue
			}
			name := rec.name
			if !rec.dir {
				if !strings.HasSuffix(name, ";1") {
					return nil, 0, errors.New("one ISO file version required")
				}
				name = strings.TrimSuffix(name, ";1")
			}
			if !isoPath(name) || strings.Contains(name, "/") || local[name] {
				return nil, 0, errors.New("invalid/duplicate directory identifier")
			}
			local[name] = true
			path := name
			if d.path != "" {
				path = d.path + "/" + name
			}
			if rec.dir {
				dirs = append(dirs, isoDir{path, rec.lba, rec.size, d.lba})
			} else {
				if len(files) >= 512 || files[path].size != 0 {
					return nil, 0, errors.New("namespace file count/duplicate bound")
				}
				if err = r.isoClaim(int64(rec.lba)*isoBlock, int64(rec.size), path, true); err != nil {
					return nil, 0, err
				}
				files[path] = isoFile{int64(rec.size), []isoExtent{{int64(rec.lba) * isoBlock, int64(rec.size)}}}
			}
		}
		if dots != 2 {
			return nil, 0, errors.New("self/parent records missing")
		}
	}
	pathSize, err := dual32(pvd[132:])
	if err != nil || pathSize == 0 || pathSize > 1<<20 {
		return nil, 0, errors.New("invalid path table size")
	}
	for _, be := range []bool{false, true} {
		off := int64(le32(pvd[140:])) * isoBlock
		if be {
			off = int64(binary.BigEndian.Uint32(pvd[148:])) * isoBlock
		}
		if off == 0 {
			return nil, 0, errors.New("required endian path table missing")
		}
		if err = r.isoClaim(off, int64(pathSize), "ISO path table", false); err != nil {
			return nil, 0, err
		}
		buf, err := r.read(off, int64(pathSize))
		if err != nil {
			return nil, 0, err
		}
		paths := []isoDir{}
		for pos := 0; pos < len(buf); {
			if len(buf)-pos < 8 {
				return nil, 0, errors.New("truncated path table")
			}
			p := buf[pos:]
			n := int(p[0])
			record := 8 + n + n%2
			if n == 0 || p[1] != 0 || record > len(p) || len(paths) >= 256 {
				return nil, 0, errors.New("invalid path table record")
			}
			if n%2 != 0 && p[8+n] != 0 {
				return nil, 0, errors.New("nonzero ISO path-table padding")
			}
			lba, parent := le32(p[2:]), le16(p[6:])
			if be {
				lba = binary.BigEndian.Uint32(p[2:])
				parent = binary.BigEndian.Uint16(p[6:])
			}
			name := string(p[8 : 8+n])
			path := ""
			if len(paths) == 0 {
				if name != "\x00" || parent != 1 || lba != root.lba {
					return nil, 0, errors.New("invalid path table root")
				}
			} else {
				if parent == 0 || int(parent) > len(paths) || !isoPath(name) || strings.Contains(name, "/") {
					return nil, 0, errors.New("invalid path table parent/name")
				}
				path = name
				if paths[parent-1].path != "" {
					path = paths[parent-1].path + "/" + name
				}
			}
			paths = append(paths, isoDir{path, lba, 0, 0})
			pos += record
		}
		if len(paths) != len(dirs) {
			return nil, 0, errors.New("directory/path table count differs")
		}
		for _, p := range paths {
			found := false
			for _, d := range dirs {
				found = found || p.path == d.path && p.lba == d.lba
			}
			if !found {
				return nil, 0, errors.New("path table and directory disagree")
			}
		}
	}
	if le32(pvd[144:]) != 0 || binary.BigEndian.Uint32(pvd[152:]) != 0 {
		return nil, 0, errors.New("unsupported additional path tables")
	}
	return files, catalog, nil
}

type isoRecordData struct {
	name      string
	lba, size uint32
	dir       bool
}

func isoRecord(p []byte) (isoRecordData, error) {
	var x isoRecordData
	if len(p) < 34 || int(p[0]) > len(p) || p[0] < 34 || p[1] != 0 || int(p[32])+33 > int(p[0]) || p[26] != 0 || p[27] != 0 || p[25]&^byte(2) != 0 {
		return x, errors.New("unsupported or malformed directory record")
	}
	var err error
	x.lba, err = dual32(p[2:])
	if err != nil {
		return x, err
	}
	x.size, err = dual32(p[10:])
	if err != nil {
		return x, err
	}
	seq, err := dual16(p[28:])
	if err != nil || seq != 1 {
		return x, errors.New("directory volume sequence mismatch")
	}
	x.name = string(p[33 : 33+int(p[32])])
	x.dir = p[25]&2 != 0
	return x, nil
}
