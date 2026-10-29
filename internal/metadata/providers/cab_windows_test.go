package providers

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"uupbuilder/internal/metadata"
)

func singleCAB(name string, body []byte) []byte {
	fileEnd := 44 + 16 + len(name) + 1
	b := make([]byte, fileEnd+8+len(body))
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], 44)
	b[24], b[25] = 3, 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], 1)
	binary.LittleEndian.PutUint32(b[36:], uint32(fileEnd))
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint32(b[44:], uint32(len(body)))
	copy(b[60:], name)
	binary.LittleEndian.PutUint16(b[fileEnd+4:], uint16(len(body)))
	binary.LittleEndian.PutUint16(b[fileEnd+6:], uint16(len(body)))
	copy(b[fileEnd+8:], body)
	return b
}

// Declared MSZIP output has no valid compressed body. Limit failures must be
// returned from the validated table, before the native extractor can see it.
func declaredCAB(names []string, sizes []int) []byte {
	fileEnd := 44
	total := 0
	for i, name := range names {
		fileEnd += 17 + len(name)
		total += sizes[i]
	}
	blocks := (total + 32767) / 32768
	b := make([]byte, fileEnd+blocks*9)
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], 44)
	b[24], b[25] = 3, 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], uint16(len(names)))
	binary.LittleEndian.PutUint32(b[36:], uint32(fileEnd))
	binary.LittleEndian.PutUint16(b[40:], uint16(blocks))
	binary.LittleEndian.PutUint16(b[42:], 1)
	at, offset := 44, 0
	for i, name := range names {
		binary.LittleEndian.PutUint32(b[at:], uint32(sizes[i]))
		binary.LittleEndian.PutUint32(b[at+4:], uint32(offset))
		copy(b[at+16:], name)
		at += 17 + len(name)
		offset += sizes[i]
	}
	remaining := total
	for at = fileEnd; remaining > 0; at += 9 {
		n := min(remaining, 32768)
		binary.LittleEndian.PutUint16(b[at+4:], 1)
		binary.LittleEndian.PutUint16(b[at+6:], uint16(n))
		b[at+8] = 'X'
		remaining -= n
	}
	return b
}

func multiRawCAB(names []string, data [][]byte) []byte {
	fileEnd, total := 44, 0
	for i, name := range names {
		fileEnd += 17 + len(name)
		total += len(data[i])
	}
	b := make([]byte, fileEnd+8+total)
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], 44)
	b[24], b[25] = 3, 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], uint16(len(names)))
	binary.LittleEndian.PutUint32(b[36:], uint32(fileEnd))
	binary.LittleEndian.PutUint16(b[40:], 1)
	at, offset := 44, 0
	for i, name := range names {
		binary.LittleEndian.PutUint32(b[at:], uint32(len(data[i])))
		binary.LittleEndian.PutUint32(b[at+4:], uint32(offset))
		copy(b[at+16:], name)
		copy(b[fileEnd+8+offset:], data[i])
		offset += len(data[i])
		at += 17 + len(name)
	}
	binary.LittleEndian.PutUint16(b[fileEnd+4:], uint16(total))
	binary.LittleEndian.PutUint16(b[fileEnd+6:], uint16(total))
	return b
}

func TestCABRefusesDeclaredDocumentBudgetsBeforeExtraction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		names  []string
		sizes  []int
		limits metadata.Limits
	}{
		{"document", []string{"oversized.xml"}, []int{8}, metadata.Limits{MaxDocumentBytes: 4}},
		{"aggregate", []string{"first.xml", "second.xml"}, []int{8, 8}, metadata.Limits{MaxDocumentBytes: 10, MaxTotalBytes: 12}},
		{"intermediate-containers", []string{"first.xml.cab", "second.xml.cab", "third.xml.cab"}, []int{16 << 20, 16 << 20, 16 << 20}, metadata.Limits{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := declaredCAB(tc.names, tc.sizes)
			if _, err := metadata.InspectCAB(context.Background(), body); err != nil {
				t.Fatalf("test cabinet table invalid: %v", err)
			}
			r := resource(t, body)
			// Existing native extraction needs this parent. Making it unavailable
			// distinguishes early refusal from limit checks after expansion/read.
			missing := filepath.Join(t.TempDir(), "not-created")
			t.Setenv("TMP", missing)
			t.Setenv("TEMP", missing)
			if _, err := (CAB{Members: tc.names}).Inspect(context.Background(), r, tc.limits); !errors.Is(err, metadata.ErrLimit) {
				t.Fatalf("budget reached extraction instead of early ErrLimit: %v", err)
			}
			if _, err := os.Stat(missing); !os.IsNotExist(err) {
				t.Fatalf("refused work created extraction storage: %v", err)
			}
		})
	}
}

func TestCABRefusesNestedAggregateBeforeInnerExpansion(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("TMP", parent)
	t.Setenv("TEMP", parent)
	first := singleCAB("first.xml", []byte("12345678"))
	second := declaredCAB([]string{"second.xml"}, []int{8})
	names := []string{"first.xml.cab", "second.xml.cab"}
	body := multiRawCAB(names, [][]byte{first, second})
	if _, err := metadata.InspectCAB(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if _, err := (CAB{Members: names}).Inspect(context.Background(), resource(t, body), metadata.Limits{MaxDocumentBytes: 10, MaxTotalBytes: 12}); !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("nested aggregate reached invalid inner expansion: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("owned extraction scopes not removed: %v %v", entries, err)
	}
}

// Native expand must extract only the selected, prevalidated nested member.
func TestCABObservesSelectedNestedXML(t *testing.T) {
	xml := []byte(`<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" BuildArch="arm64" Type="Build" BuildID="test"/>`)
	r := resource(t, singleCAB("target.xml.cab", singleCAB("target.xml", xml)))
	got, err := (CAB{Members: []string{"TARGET.XML.CAB"}}).Inspect(context.Background(), r, metadata.Limits{})
	if err != nil || len(got.Documents) != 1 || string(got.Documents[0].Original) != string(xml) || got.Documents[0].Resource.Member != "target.xml.cab/target.xml" {
		t.Fatalf("CAB result: %+v %v", got, err)
	}
	if _, err := (CAB{Members: []string{"absent.xml.cab"}}).Inspect(context.Background(), r, metadata.Limits{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing metadata schema classified as payload absence: %v", err)
	}
}
