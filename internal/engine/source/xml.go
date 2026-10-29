package source

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
)

func selectedXML(ctx context.Context, in Inputs, receipt wimindex.MetadataReceipt, l Limits) (out []byte, original string, inv metadata.Inventory, runErr error) {
	d := receipt.Header.XML
	if d.Size == 0 || d.Size > uint64(l.MaxXMLBytes) || d.Size != d.Original || d.Flags & ^byte(2) != 0 || d.Offset > uint64(receipt.Payload.Size) || d.Size > uint64(receipt.Payload.Size)-d.Offset {
		return nil, "", inv, ErrInput
	}
	if uint64(receipt.Payload.Size)*2+d.Size > l.MaxReadBytes || d.Size*16 > l.MaxResultBytes {
		return nil, "", inv, ErrLimit
	}
	var selected metadata.LocalResource
	found := false
	for _, f := range in.Files {
		if f.Identity == receipt.Payload {
			if found {
				return nil, "", inv, ErrInput
			}
			found = true
			selected = f
		}
	}
	if !found {
		return nil, "", inv, ErrInput
	}
	f, initial, e := localsource.Open(selected.Path, selected.Identity)
	if e != nil {
		return nil, "", inv, e
	}
	defer func() { runErr = errors.Join(runErr, f.Close()) }()
	check := func() error {
		s, e := localsource.Verify(ctx, f, selected.Path, selected.Identity, initial)
		if e != nil || s != receipt.SourceSHA256 {
			return errors.Join(ErrIntegrity, e)
		}
		return nil
	}
	if e = check(); e != nil {
		return nil, "", inv, e
	}
	raw := make([]byte, int(d.Size))
	if n, e := f.ReadAt(raw, int64(d.Offset)); e != nil || n != len(raw) {
		return nil, "", inv, ErrIntegrity
	}
	original = bytesDigest(raw)
	text, e := decodeXML(raw)
	if e != nil {
		return nil, "", inv, e
	}
	image, e := oneImage(text, int(receipt.Entry.ImageIndex))
	if e != nil {
		return nil, "", inv, e
	}
	// VERSION tag names are uppercase in WIM XML.
	var semantics struct {
		Windows struct {
			Architecture string `xml:"ARCH"`
			Edition      string `xml:"EDITIONID"`
			Type         string `xml:"INSTALLATIONTYPE"`
			Version      struct {
				Major   string `xml:"MAJOR"`
				Minor   string `xml:"MINOR"`
				Build   string `xml:"BUILD"`
				SPBuild string `xml:"SPBUILD"`
			} `xml:"VERSION"`
		} `xml:"WINDOWS"`
	}
	if e = xml.Unmarshal(image, &semantics); e != nil {
		return nil, "", inv, ErrInput
	}
	s := semantics.Windows
	architecture := model.Architecture(s.Architecture)
	switch s.Architecture {
	case "0":
		architecture = "x86"
	case "9":
		architecture = "amd64"
	case "12":
		architecture = "arm64"
	}
	version := strings.Join([]string{s.Version.Major, s.Version.Minor, s.Version.Build, s.Version.SPBuild}, ".")
	inv = metadata.Inventory{Source: in.Manifest.Source, Manifest: in.Manifest, Images: []metadata.Image{{Index: int(receipt.Entry.ImageIndex), Resource: metadata.ResourceReference{Payload: receipt.Payload, Member: "wim.xml"}, Architecture: architecture, Edition: s.Edition, InstallationType: s.Type, Build: version}}}
	out = encodeXML("<WIM>" + string(image) + "</WIM>")
	if len(out) > l.MaxXMLBytes {
		return nil, "", inv, ErrLimit
	}
	if e = check(); e != nil {
		return nil, "", inv, e
	}
	return out, original, inv, nil
}
func verifyMetadata(ctx context.Context, r io.ReaderAt, w wimindex.MetadataReceipt) error {
	h1, h256 := sha1.New(), sha256.New()
	var b [64 << 10]byte
	for off := uint64(0); off < w.Size; {
		if e := ctx.Err(); e != nil {
			return e
		}
		n := min(uint64(len(b)), w.Size-off)
		got, e := r.ReadAt(b[:n], int64(off))
		if e != nil || uint64(got) != n {
			return errors.Join(ErrIntegrity, e)
		}
		h1.Write(b[:n])
		h256.Write(b[:n])
		off += n
	}
	if hex.EncodeToString(h1.Sum(nil)) != w.SHA1 || hex.EncodeToString(h256.Sum(nil)) != w.SHA256 {
		return ErrIntegrity
	}
	return ctx.Err()
}
func decodeXML(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, ErrInput
	}
	u := make([]uint16, len(raw)/2)
	for n := range u {
		u[n] = binary.LittleEndian.Uint16(raw[n*2:])
	}
	if len(u) > 0 && u[0] == 0xfeff {
		u = u[1:]
	}
	for n := 0; n < len(u); n++ {
		if u[n] >= 0xd800 && u[n] <= 0xdbff {
			if n+1 >= len(u) || u[n+1] < 0xdc00 || u[n+1] > 0xdfff {
				return nil, ErrInput
			}
			n++
		} else if u[n] >= 0xdc00 && u[n] <= 0xdfff {
			return nil, ErrInput
		}
	}
	return []byte(string(utf16.Decode(u))), nil
}
func encodeXML(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+len(u)*2)
	b[0] = 0xff
	b[1] = 0xfe
	for n, v := range u {
		binary.LittleEndian.PutUint16(b[2+n*2:], v)
	}
	return b
}

// Rebuild only the IMAGE start framing; carry its complete original body and
// unknown fields unchanged. INDEX comes from the mapped metadata ordinal.
func oneImage(text []byte, index int) ([]byte, error) {
	d := xml.NewDecoder(bytes.NewReader(text))
	depth := 0
	start, endStart, end := -1, -1, -1
	var framing xml.StartElement
	for {
		before := int(d.InputOffset())
		token, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, ErrInput
		}
		switch t := token.(type) {
		case xml.StartElement:
			// This first rule cannot relocate an outer namespace context into
			// rebuilt container framing without changing opaque XML semantics.
			if t.Name.Space != "" {
				return nil, ErrInput
			}
			for _, a := range t.Attr {
				if a.Name.Space != "" || a.Name.Local == "xmlns" {
					return nil, ErrInput
				}
			}
			depth++
			if depth == 2 && t.Name.Local == "IMAGE" {
				for _, a := range t.Attr {
					if a.Name.Local == "INDEX" && a.Name.Space == "" && a.Value == strconv.Itoa(index) {
						if start != -1 {
							return nil, ErrInput
						}
						start = before
						endStart = int(d.InputOffset())
						framing = t
					}
				}
			}
		case xml.EndElement:
			if depth == 2 && start >= 0 && end < 0 {
				end = int(d.InputOffset())
			}
			depth--
		case xml.Directive:
			return nil, ErrInput
		}
	}
	if start < 0 || end < endStart {
		return nil, ErrInput
	}
	for n := range framing.Attr {
		if framing.Attr[n].Name.Local == "INDEX" && framing.Attr[n].Name.Space == "" {
			framing.Attr[n].Value = "1"
		}
	}
	var b bytes.Buffer
	enc := xml.NewEncoder(&b)
	if e := enc.EncodeToken(framing); e != nil {
		return nil, e
	}
	if e := enc.Flush(); e != nil {
		return nil, e
	}
	b.Write(text[endStart:end])
	return b.Bytes(), nil
}
