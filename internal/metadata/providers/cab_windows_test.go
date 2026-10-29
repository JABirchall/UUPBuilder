package providers

import (
	"context"
	"encoding/binary"
	"errors"
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
