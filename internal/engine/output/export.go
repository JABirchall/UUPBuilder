package output

import (
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

func fileIdentity(ctx context.Context, path string) (File, error) {
	f, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() {
		return File{}, ErrVerification
	}
	n, h, err := digest(ctx, f)
	return File{path, h, n}, err
}
func checkFile(ctx context.Context, want File) error {
	got, err := fileIdentity(ctx, want.Path)
	if err != nil {
		return err
	}
	if got != want {
		return ErrVerification
	}
	return nil
}

// Prepare exports the internal image representation and independently reads
// its image metadata after the native exporter has verified resource integrity.
func Prepare(ctx context.Context, req ExportRequest, exporter Exporter) (ExportResult, error) {
	var out ExportResult
	if ctx == nil || req.Plan.Validate() != nil || exporter == nil {
		return out, ErrVerification
	}
	p := req.Plan.CustomizationPlan()
	if p == nil || req.Customized.PlanDigest != p.Digest {
		return out, ErrVerification
	}
	if err := validateCustomized(*p, req.Customized); err != nil {
		return out, err
	}
	var input File
	matches := 0
	for _, f := range req.Customized.Outputs {
		if filepath.Base(f.Path) == filepath.Base(req.Customized.WIMPath) {
			matches++
			input = File{req.Customized.WIMPath, f.SHA256, f.Size}
		}
	}
	if matches != 1 {
		return out, fmt.Errorf("%w: customized image receipt missing or ambiguous", ErrVerification)
	}
	if err := checkFile(ctx, input); err != nil {
		return out, err
	}
	if err := os.Mkdir(req.Directory, 0700); err != nil {
		return out, err
	}
	s := req.Plan.EffectiveSettings().Output
	dst := filepath.Join(req.Directory, "install."+string(s.ImageFormat))
	if err := exporter.Export(ctx, input.Path, dst, s.ImageFormat, s.SplitSizeMiB); err != nil {
		return out, err
	}
	if err := checkFile(ctx, input); err != nil {
		return out, err
	}
	entries, err := os.ReadDir(req.Directory)
	if err != nil {
		return out, err
	}
	if len(entries) == 0 {
		return out, fmt.Errorf("%w: exporter produced no files", ErrVerification)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			return out, ErrVerification
		}
		if s.ImageFormat != model.ImageSWM && name != filepath.Base(dst) {
			return out, ErrVerification
		}
		if s.ImageFormat == model.ImageSWM && (name != "install.swm" && (!strings.HasPrefix(name, "install") || !strings.HasSuffix(name, ".swm"))) {
			return out, ErrVerification
		}
		f, e := fileIdentity(ctx, filepath.Join(req.Directory, name))
		if e != nil {
			return out, e
		}
		out.Files = append(out.Files, f)
	}
	sort.Slice(out.Files, func(i, j int) bool { return partNumber(out.Files[i].Path) < partNumber(out.Files[j].Path) })
	for i, f := range out.Files {
		if s.ImageFormat == model.ImageSWM && partNumber(f.Path) != i+1 {
			return ExportResult{}, ErrVerification
		}
	}
	if err = exporter.VerifyImage(ctx, dst, s.ImageFormat); err != nil {
		return ExportResult{}, err
	}
	f, err := os.Open(dst)
	if err != nil {
		return ExportResult{}, err
	}
	images, err := inspectImage(f, out.Files[0].Size)
	f.Close()
	if err != nil {
		return ExportResult{}, err
	}
	if !sameImages(images, req.Customized.Images) {
		return ExportResult{}, fmt.Errorf("%w: exported edition/architecture/language order differs", ErrVerification)
	}
	out.PlanDigest = req.Plan.Digest()
	out.Source = req.Plan.Manifest().Source
	out.Format = s.ImageFormat
	out.Images = images
	out.Customization = req.Customized
	if reporter, ok := exporter.(ToolReporter); ok {
		out.Tools, err = reporter.ToolIdentities(ctx)
		if err != nil {
			return ExportResult{}, err
		}
	}
	return out, ctx.Err()
}
func partNumber(path string) int {
	name := filepath.Base(path)
	if name == "install.swm" || name == "install.wim" || name == "install.esd" {
		return 1
	}
	n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "install"), ".swm"))
	if n < 2 || name != fmt.Sprintf("install%d.swm", n) {
		return 0
	}
	return n
}
func sameImages(a, b []service.ImageIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.Index != i+1 || y.Index != i+1 || !strings.EqualFold(x.Edition, y.Edition) || x.Architecture != y.Architecture || !strings.EqualFold(x.Language, y.Language) {
			return false
		}
	}
	return true
}
func validateCustomized(p planner.CustomizationPlan, c service.CustomizedImages) error {
	if len(c.Images) != len(p.Editions) || len(c.Observations) != len(p.Editions) || p.Apps.Deferred {
		return ErrVerification
	}
	for i, e := range p.Editions {
		image, obs := c.Images[i], c.Observations[i]
		if image.Index != i+1 || !strings.EqualFold(image.Edition, e) || image.Architecture != p.Source.Architecture || !strings.EqualFold(image.Language, p.Source.Language) || !strings.EqualFold(obs.Edition, e) {
			return ErrVerification
		}
		for _, op := range p.Apps.Provision {
			want := op.ObservedIdentity()
			found := false
			for _, a := range obs.Apps {
				arch := a.Architecture
				if arch == "x64" {
					arch = "amd64"
				}
				wantArch := want.Architecture
				if wantArch == "x64" {
					wantArch = "amd64"
				}
				found = found || strings.EqualFold(a.Name, want.Name) && a.Version == want.Version && a.ResourceID == want.ResourceID && a.PublisherID == metadata.PublisherID(want.Publisher) && arch == wantArch
			}
			if !found {
				return fmt.Errorf("%w: requested app %s absent", ErrVerification, want.Name)
			}
		}
		for _, op := range p.Apps.Remove {
			for _, a := range obs.Apps {
				if strings.EqualFold(a.Name, op.Name) && a.PublisherID == metadata.PublisherID(op.Publisher) {
					return ErrVerification
				}
			}
		}
		for _, feature := range p.Features {
			state := obs.Features[feature.Name]
			if feature.Enable && state != "Enabled" && state != "Enable Pending" {
				return ErrVerification
			}
		}
	}
	return nil
}

func inspectImage(r io.ReaderAt, size int64) ([]service.ImageIdentity, error) {
	var h [208]byte
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return nil, err
	}
	if string(h[:8]) != "MSWIM\x00\x00\x00" || binary.LittleEndian.Uint32(h[8:]) != 208 {
		return nil, ErrVerification
	}
	version := binary.LittleEndian.Uint32(h[12:])
	if version != 0x10d00 && version != 0xe00 {
		return nil, ErrVerification
	}
	if binary.LittleEndian.Uint16(h[40:]) != 1 || binary.LittleEndian.Uint16(h[42:]) < 1 {
		return nil, ErrVerification
	}
	packed := binary.LittleEndian.Uint64(h[72:])
	n, flags := packed&0x00ffffffffffffff, byte(packed>>56)
	off, original := binary.LittleEndian.Uint64(h[80:]), binary.LittleEndian.Uint64(h[88:])
	if n == 0 || n > 8<<20 || n != original || flags&^byte(2) != 0 || off < 208 || off > uint64(size) || n > uint64(size)-off {
		return nil, ErrVerification
	}
	b := make([]byte, n)
	if _, err := r.ReadAt(b, int64(off)); err != nil {
		return nil, err
	}
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		if len(b)%2 != 0 {
			return nil, ErrVerification
		}
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2+i*2:])
		}
		b = []byte(string(utf16.Decode(u)))
	}
	// WIM XML often declares UTF-16; bytes have already been decoded above.
	text := string(b)
	if strings.HasPrefix(text, "<?xml") {
		if end := strings.Index(text, "?>"); end >= 0 {
			text = text[end+2:]
		}
	}
	var w struct {
		XMLName xml.Name `xml:"WIM"`
		Images  []struct {
			Index   int `xml:"INDEX,attr"`
			Windows struct {
				Arch      string   `xml:"ARCH"`
				Edition   string   `xml:"EDITIONID"`
				Languages []string `xml:"LANGUAGES>LANGUAGE"`
			} `xml:"WINDOWS"`
		} `xml:"IMAGE"`
	}
	if err := xml.Unmarshal([]byte(text), &w); err != nil {
		return nil, err
	}
	if len(w.Images) == 0 || len(w.Images) > 256 || len(w.Images) != int(binary.LittleEndian.Uint32(h[44:])) {
		return nil, ErrVerification
	}
	var out []service.ImageIdentity
	for i, x := range w.Images {
		arch := map[string]model.Architecture{"0": "x86", "9": "amd64", "12": "arm64"}[x.Windows.Arch]
		if x.Index != i+1 || arch == "" || x.Windows.Edition == "" || len(x.Windows.Languages) == 0 {
			return nil, errors.New("internal WIM identity incomplete")
		}
		out = append(out, service.ImageIdentity{Index: x.Index, Edition: x.Windows.Edition, Architecture: arch, Language: x.Windows.Languages[0]})
	}
	return out, nil
}
