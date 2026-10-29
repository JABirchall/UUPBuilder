package wimindex

import (
	"context"
	"encoding/xml"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Only the independent image index and descriptive XML fields are observed.
// Missing semantic role fields stay empty; neither names nor boot status fill them.
func readImages(ctx context.Context, r io.ReaderAt, size uint64, c Container, l Limits) ([]Image, []Gap, error) {
	d := c.Header.XML
	unresolved := func(capability string) ([]Image, []Gap, error) { return nil, []Gap{gap(c.Payload, 0, capability)}, nil }
	if d.Size == 0 {
		return unresolved("missing-image-XML")
	}
	if d.Flags != 0 && d.Flags != 2 {
		return unresolved("image-XML-encoding")
	}
	if d.Size != d.Original {
		return nil, nil, ErrLayout
	}
	if d.Size > uint64(l.MaxXMLBytes) {
		return nil, nil, ErrLimit
	}
	b := make([]byte, int(d.Size))
	if err := readRange(ctx, r, size, d.Offset, b); err != nil {
		return nil, nil, err
	}
	if len(b)%2 != 0 {
		return nil, nil, ErrLayout
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = disk.Uint16(b[i*2:])
	}
	if len(u) > 0 && u[0] == 0xfffe {
		return unresolved("image-XML-big-endian")
	}
	if len(u) > 0 && u[0] == 0xfeff {
		u = u[1:]
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return nil, nil, ErrLayout
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return nil, nil, ErrLayout
		}
	}
	decoder := xml.NewDecoder(strings.NewReader(string(utf16.Decode(u))))
	// The byte stream has already been decoded from UTF16LE. Honor its usual
	// XML declaration without trying to decode the now-UTF8 string a second time.
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "utf-16") || strings.EqualFold(charset, "utf-16le") {
			return input, nil
		}
		return nil, ErrLayout
	}
	var path []string
	var images []Image
	var current *Image
	var version [4]string
	seen := map[uint32]bool{}
	var fields map[string]bool
	tokens := 0
	rootSeen := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, ErrLayout
		}
		tokens++
		if tokens > 65536 {
			return nil, nil, ErrLimit
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Space != "" {
				return unresolved("image-XML-namespace")
			}
			path = append(path, t.Name.Local)
			if len(path) > 64 {
				return nil, nil, ErrLimit
			}
			if len(path) == 1 {
				if rootSeen || t.Name.Local != "WIM" {
					return nil, nil, ErrLayout
				}
				rootSeen = true
			}
			key := strings.Join(path, "/")
			if key == "WIM/IMAGE" {
				index := uint64(0)
				attrs := 0
				for _, a := range t.Attr {
					if a.Name.Local == "INDEX" && a.Name.Space == "" {
						attrs++
						index, err = strconv.ParseUint(a.Value, 10, 32)
						if err != nil {
							return nil, nil, ErrLayout
						}
					}
				}
				if attrs != 1 || index == 0 || index > uint64(c.Header.ImageCount) || seen[uint32(index)] {
					return nil, nil, ErrLayout
				}
				seen[uint32(index)] = true
				images = append(images, Image{Index: uint32(index)})
				current = &images[len(images)-1]
				version = [4]string{}
				fields = map[string]bool{}
			} else if current != nil && (key == "WIM/IMAGE/WINDOWS" || key == "WIM/IMAGE/WINDOWS/VERSION" || xmlField(key)) {
				if fields[key] {
					return nil, nil, ErrLayout
				}
				fields[key] = true
			}
		case xml.CharData:
			key := strings.Join(path, "/")
			if current == nil {
				continue
			}
			switch key {
			case "WIM/IMAGE/WINDOWS/ARCH":
				current.Architecture += string(t)
			case "WIM/IMAGE/WINDOWS/EDITIONID":
				current.Edition += string(t)
			case "WIM/IMAGE/WINDOWS/INSTALLATIONTYPE":
				current.InstallationType += string(t)
			case "WIM/IMAGE/WINDOWS/VERSION/MAJOR":
				version[0] += string(t)
			case "WIM/IMAGE/WINDOWS/VERSION/MINOR":
				version[1] += string(t)
			case "WIM/IMAGE/WINDOWS/VERSION/BUILD":
				version[2] += string(t)
			case "WIM/IMAGE/WINDOWS/VERSION/SPBUILD":
				version[3] += string(t)
			}
		case xml.EndElement:
			if strings.Join(path, "/") == "WIM/IMAGE" {
				current.Architecture = strings.TrimSpace(current.Architecture)
				current.Edition = strings.TrimSpace(current.Edition)
				current.InstallationType = strings.TrimSpace(current.InstallationType)
				for i := range version {
					version[i] = strings.TrimSpace(version[i])
				}
				if version[0] != "" && version[1] != "" && version[2] != "" {
					current.Version = strings.Join(version[:3], ".")
					if version[3] != "" {
						current.Version += "." + version[3]
					}
				}
				current = nil
			}
			path = path[:len(path)-1]
		case xml.Directive:
			return unresolved("image-XML-directive")
		}
	}
	if !rootSeen {
		return nil, nil, ErrLayout
	}
	slices.SortFunc(images, func(a, b Image) int { return int(a.Index) - int(b.Index) })
	if len(images) != int(c.Header.ImageCount) {
		return images, []Gap{gap(c.Payload, 0, "XML-image-count")}, nil
	}
	return images, nil, nil
}
func xmlField(key string) bool {
	switch key {
	case "WIM/IMAGE/WINDOWS/ARCH", "WIM/IMAGE/WINDOWS/EDITIONID", "WIM/IMAGE/WINDOWS/INSTALLATIONTYPE", "WIM/IMAGE/WINDOWS/VERSION/MAJOR", "WIM/IMAGE/WINDOWS/VERSION/MINOR", "WIM/IMAGE/WINDOWS/VERSION/BUILD", "WIM/IMAGE/WINDOWS/VERSION/SPBUILD":
		return true
	}
	return false
}
