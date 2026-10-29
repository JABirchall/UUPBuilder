package source

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

type ImageSummary struct{ Directories, Files, TotalBytes, HardlinkBytes uint64 }

// The source's Windows counters exclude the root directory. Stream sizes are
// logical per dentry, including ADS/reparse streams. HARDLINKBYTES counts each
// additional name of the same inode; unrelated identical bytes are not links.
// Pinned wimlib v1.14.5 xml.c uses this stream/link accounting. Every original
// source counter must independently agree before any output scalar is changed.
func recordSummary(nodes []setupNode, sizes map[string]uint64, launch int, replacement string) (ImageSummary, error) {
	var s ImageSummary
	links := map[uint64]bool{}
	for i, n := range nodes {
		if n.entry.Attributes&16 != 0 {
			if n.entry.Parent >= 0 {
				s.Directories++
			}
		} else {
			s.Files++
		}
		var size uint64
		for _, stream := range n.entry.Streams {
			key := stream.SHA1
			if i == launch {
				key = replacement
			}
			if key == "0000000000000000000000000000000000000000" {
				continue
			}
			v, ok := sizes[key]
			if !ok {
				return s, ErrInput
			}
			if v > ^uint64(0)-size {
				return s, ErrLimit
			}
			size += v
		}
		if size > ^uint64(0)-s.TotalBytes {
			return s, ErrLimit
		}
		s.TotalBytes += size
		if n.entry.HardlinkID != 0 {
			if links[n.entry.HardlinkID] {
				if size > ^uint64(0)-s.HardlinkBytes {
					return s, ErrLimit
				}
				s.HardlinkBytes += size
			}
			links[n.entry.HardlinkID] = true
		}
	}
	return s, nil
}
func (r *BoundSetupBoot) rewriteSummaryXML(base []boundResource) error {
	sizes := make(map[string]uint64, len(base))
	for _, v := range base {
		sizes[v.identity.SHA1] = v.identity.Size
	}
	original, e := recordSummary(r.nodes[:r.state.OriginalRecords], sizes, -1, "")
	if e != nil {
		return e
	}
	sizes = make(map[string]uint64, len(r.resources))
	for _, v := range r.resources {
		sizes[v.identity.SHA1] = v.identity.Size
	}
	output, e := recordSummary(r.nodes, sizes, r.paths[launchPath], r.state.LaunchSHA1)
	if e != nil {
		return e
	}
	text, e := decodeXML(r.xml)
	if e != nil {
		return e
	}
	modified, e := replaceImageSummaries(text, original, output)
	if e != nil {
		return e
	}
	r.xml = encodeXML(string(modified))
	if len(r.xml) > r.limits.MaxXMLBytes {
		return ErrLimit
	}
	r.state.OriginalSummary = original
	r.state.OutputSummary = output
	r.state.XMLBytes = uint64(len(r.xml))
	r.state.OutputXMLSHA256 = bytesDigest(r.xml)
	return nil
}

// Replace only the decimal text spans of four direct IMAGE children. Every
// other body/label byte remains untouched; missing, duplicate, nested, escaped
// or mismatched baseline summaries are unsupported source shapes.
func replaceImageSummaries(text []byte, original, output ImageSummary) ([]byte, error) {
	names := map[string]int{"DIRCOUNT": 0, "FILECOUNT": 1, "TOTALBYTES": 2, "HARDLINKBYTES": 3}
	want := [4]uint64{original.Directories, original.Files, original.TotalBytes, original.HardlinkBytes}
	next := [4]uint64{output.Directories, output.Files, output.TotalBytes, output.HardlinkBytes}
	type replacement struct {
		start, end int
		value      string
	}
	changes := []replacement{}
	seen := [4]bool{}
	depth, start, active := 0, -1, -1
	d := xml.NewDecoder(bytes.NewReader(text))
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
			depth++
			if depth == 3 {
				if n, ok := names[t.Name.Local]; ok {
					if active != -1 || seen[n] || t.Name.Space != "" || len(t.Attr) != 0 {
						return nil, ErrSetupShape
					}
					active = n
					start = int(d.InputOffset())
				}
			} else if active != -1 {
				return nil, ErrSetupShape
			}
		case xml.EndElement:
			if depth == 3 && active != -1 {
				value, e := strconv.ParseUint(strings.TrimSpace(string(text[start:before])), 10, 64)
				if e != nil || value != want[active] {
					return nil, fmt.Errorf("%w: original IMAGE summary %s differs from complete record streams", ErrSetupShape, t.Name.Local)
				}
				changes = append(changes, replacement{start, before, strconv.FormatUint(next[active], 10)})
				seen[active] = true
				active = -1
			}
			depth--
		case xml.Directive:
			return nil, ErrSetupShape
		}
	}
	for _, ok := range seen {
		if !ok {
			return nil, ErrSetupShape
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].start < changes[j].start })
	var b bytes.Buffer
	b.Grow(len(text) + 80)
	off := 0
	for _, c := range changes {
		b.Write(text[off:c.start])
		b.WriteString(c.value)
		off = c.end
	}
	b.Write(text[off:])
	return b.Bytes(), nil
}
