package isocontent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const windowsLimit int64 = 128 << 30

func windowsPath(p string) bool {
	if p == "" || len(p) > 1024 || strings.ContainsAny(p, "\\:\x00") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
		for _, r := range part {
			if r < 32 {
				return false
			}
		}
	}
	return true
}
func windowsExpectations(e ISOExpectations) (map[string]ISOExpectedFile, error) {
	if e.Volume == "" || len(e.Volume) > 32 || len(e.Files) == 0 || len(e.Files) > 32768 {
		return nil, errors.New("invalid Windows media expectations")
	}
	w := map[string]ISOExpectedFile{}
	seen := map[string]bool{}
	for _, f := range e.Files {
		if !windowsPath(f.Path) || f.Size < 0 || f.Size > windowsLimit || !isoHash(f.SHA256) || seen[strings.ToLower(f.Path)] {
			return nil, errors.New("invalid Windows media file")
		}
		w[f.Path] = f
		seen[strings.ToLower(f.Path)] = true
	}
	loader, _ := isoEFIBinding(e.TargetMachine)
	if loader == "" || !strings.EqualFold(e.DirectLoaderPath, loader) || w[e.DirectLoaderPath].Size == 0 || w[e.BootImagePath].Size == 0 || !strings.EqualFold(e.EmbeddedLoader.Path, loader) || !isoHash(e.EmbeddedLoader.SHA256) {
		return nil, errors.New("source EFI bindings required")
	}
	if e.BIOSBootImagePath != "" && w[e.BIOSBootImagePath].Size == 0 {
		return nil, errors.New("source BIOS binding required")
	}
	return w, nil
}

// InspectWindowsISO inspects every file in the authoritative UDF 1.02
// namespace and source-bound BIOS/EFI catalog entries. The ISO9660 fallback
// namespace may use shortened names and is not used as Windows Setup content.
func InspectWindowsISO(reader io.ReaderAt, size int64, e ISOExpectations) (ISOInspection, error) {
	_, result, err := openWindowsISO(reader, size, e)
	return result, err
}

// WindowsFile returns a bounded view after the complete image was inspected.
// The caller must retain the underlying ReaderAt for the view's lifetime.
func WindowsFile(reader io.ReaderAt, size int64, e ISOExpectations, path string) (io.ReaderAt, int64, error) {
	r, _, err := openWindowsISO(reader, size, e)
	if err != nil {
		return nil, 0, err
	}
	f, ok := r.files[path]
	if !ok {
		return nil, 0, errors.New("ISO file absent")
	}
	return extentReader{reader, f}, f.size, nil
}

type windowsImage struct{ files map[string]isoFile }

type Contents struct {
	image      windowsImage
	reader     io.ReaderAt
	Inspection ISOInspection
}

func OpenWindowsISO(reader io.ReaderAt, size int64, e ISOExpectations) (*Contents, error) {
	x, inspection, err := openWindowsISO(reader, size, e)
	if err != nil {
		return nil, err
	}
	return &Contents{x, reader, inspection}, nil
}
func (c *Contents) File(path string) (io.ReaderAt, int64, error) {
	if c == nil {
		return nil, 0, errors.New("no inspected ISO")
	}
	f, ok := c.image.files[path]
	if !ok {
		return nil, 0, errors.New("ISO file absent")
	}
	return extentReader{c.reader, f}, f.size, nil
}

func openWindowsISO(reader io.ReaderAt, size int64, e ISOExpectations) (windowsImage, ISOInspection, error) {
	var result ISOInspection
	if reader == nil || size < 600*isoBlock || size > windowsLimit || size%isoBlock != 0 {
		return windowsImage{}, result, errors.New("invalid Windows ISO length")
	}
	want, err := windowsExpectations(e)
	if err != nil {
		return windowsImage{}, result, err
	}
	r := &isoReader{ReaderAt: reader, size: size, isoSize: size, windowsMedia: true}
	var catalog uint32
	terminated := false
	for n := int64(16); n < 80; n++ {
		p, er := r.read(n*isoBlock, isoBlock)
		if er != nil {
			return windowsImage{}, result, er
		}
		if string(p[1:6]) != "CD001" {
			break
		}
		if p[6] != 1 {
			return windowsImage{}, result, errors.New("invalid descriptor")
		}
		if er = r.claim(n*isoBlock, isoBlock, "ISO descriptor", false); er != nil {
			return windowsImage{}, result, er
		}
		switch p[0] {
		case 0:
			if catalog != 0 || strings.TrimRight(string(p[7:39]), "\x00 ") != "EL TORITO SPECIFICATION" {
				return windowsImage{}, result, errors.New("invalid boot descriptor")
			}
			catalog = le32(p[71:])
		case 255:
			terminated = true
		}
		if terminated {
			break
		}
	}
	if catalog == 0 || !terminated {
		return windowsImage{}, result, errors.New("boot descriptor/terminator absent")
	}
	files, err := r.udf(e.Volume)
	if err != nil {
		return windowsImage{}, result, fmt.Errorf("UDF: %w", err)
	}
	result.UDFFiles, err = r.verifyFiles(files, want)
	if err != nil {
		return windowsImage{}, result, err
	}
	result.EmbeddedMachine, result.DirectMachine, err = r.windowsBoot(catalog, files, e)
	if err != nil {
		return windowsImage{}, result, err
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.NewSectionReader(reader, 0, size)); err != nil {
		return windowsImage{}, result, err
	}
	result.Size = size
	result.SHA256 = hex.EncodeToString(h.Sum(nil))
	return windowsImage{files}, result, nil
}

func (r *isoReader) windowsBoot(catalog uint32, files map[string]isoFile, e ISOExpectations) (uint16, uint16, error) {
	if err := r.claim(int64(catalog)*isoBlock, isoBlock, "El Torito catalog", false); err != nil {
		return 0, 0, err
	}
	p, err := r.read(int64(catalog)*isoBlock, isoBlock)
	if err != nil {
		return 0, 0, err
	}
	var sum uint16
	for i := 0; i < 32; i += 2 {
		sum += le16(p[i:])
	}
	platform := byte(0xef)
	if e.BIOSBootImagePath != "" {
		platform = 0
	}
	if p[0] != 1 || p[1] != platform || p[30] != 0x55 || p[31] != 0xaa || sum != 0 {
		return 0, 0, errors.New("invalid source boot catalog")
	}
	entry := p[32:64]
	end := 64
	verify := func(entry []byte, path string) (int64, error) {
		f, ok := files[path]
		if !ok || entry[0] != 0x88 || entry[1] != 0 || le16(entry[2:]) != 0 || entry[4] != 0 || entry[5] != 0 {
			return 0, errors.New("invalid no-emulation boot entry")
		}
		off := int64(le32(entry[8:])) * isoBlock
		load := int64(le16(entry[6:])) * 512
		if load <= 0 || load > (f.size+511)/512*512 || f.size > 8<<20 {
			return 0, errors.New("boot load bounds")
		}
		if err := r.bounds(off, f.size); err != nil {
			return 0, err
		}
		if err := r.claim(off, f.size, path, true); err != nil {
			return 0, err
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(r.ReaderAt, off, f.size)); err != nil {
			return 0, err
		}
		for _, want := range e.Files {
			if want.Path == path && hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
				return 0, errors.New("catalog boot bytes differ from source")
			}
		}
		return off, nil
	}
	if e.BIOSBootImagePath != "" {
		if _, err = verify(entry, e.BIOSBootImagePath); err != nil {
			return 0, 0, err
		}
		if p[64] != 0x91 || p[65] != 0xef || le16(p[66:]) != 1 {
			return 0, 0, errors.New("one final EFI catalog section required")
		}
		entry = p[96:128]
		end = 128
	}
	for _, v := range p[end:] {
		if v != 0 {
			return 0, 0, errors.New("unexpected extra boot entry")
		}
	}
	off, err := verify(entry, e.BootImagePath)
	if err != nil {
		return 0, 0, err
	}
	loader := e.EmbeddedLoader
	loader.Path, _ = isoEFIBinding(e.TargetMachine)
	embedded, err := inspectEFIFAT(io.NewSectionReader(r.ReaderAt, off, files[e.BootImagePath].size), files[e.BootImagePath].size, loader, e.TargetMachine)
	if err != nil {
		return 0, 0, err
	}
	f := files[e.DirectLoaderPath]
	direct, err := inspectEFIPE(extentReader{r.ReaderAt, f}, f.size, e.TargetMachine)
	return embedded, direct, err
}
