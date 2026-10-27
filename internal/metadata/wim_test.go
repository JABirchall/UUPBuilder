package metadata

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"unicode/utf16"
)

// Compression/BOM decoding must not replace the retained original bytes, and
// independently named images must keep their declared edition and language.
func TestCompressedAndUTF16WIMRetainOriginalMetadata(t *testing.T) {
	text := `<?xml version="1.0" encoding="utf-16"?><WIM><IMAGE INDEX="8"><WINDOWS><ARCH>12</ARCH><EDITIONID>FutureEdition</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-US</LANGUAGE></LANGUAGES></WINDOWS></IMAGE></WIM>`
	units := utf16.Encode([]rune(text))
	raw := []byte{0xff, 0xfe}
	for _, unit := range units {
		raw = binary.LittleEndian.AppendUint16(raw, unit)
	}
	for _, compressed := range []bool{false, true} {
		original := raw
		if compressed {
			var buf bytes.Buffer
			writer := gzip.NewWriter(&buf)
			_, _ = writer.Write(raw)
			_ = writer.Close()
			original = buf.Bytes()
		}
		file := inputFile(t, "opaque.data", string(original), FormatWIMXML)
		file.Gzip = compressed
		inv, err := Inspect(context.Background(), requestFor(t, file))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(inv.Documents[0].Original, original) || inv.Images[0].Index != 8 || inv.Images[0].Edition != "FutureEdition" || !reflect.DeepEqual(inv.Images[0].Languages, []string{"en-US"}) {
			t.Fatalf("original/properties lost: %#v", inv.Images)
		}
	}
}

// Unknown binary formats are implementation gaps, even if their first bytes
// happen to resemble a malformed BOM for a supported text encoding.
func TestUnknownBinaryFormatStaysImplementationGap(t *testing.T) {
	file := inputFile(t, "future.bin", string([]byte{0xff, 0xfe, 0x01}), Format("future-container"))
	inv, err := Inspect(context.Background(), requestFor(t, file))
	if err != nil || inv.Classification != ClassificationImplementationGap {
		t.Fatalf("want unsupported-format gap, got %q %v", inv.Classification, err)
	}
}

// Cancellation or contradictory source/manifest inputs must not reach parsing.
func TestInspectionRejectsInvalidInputsAndCancellation(t *testing.T) {
	file := inputFile(t, "metadata.xml", `<WIM/>`, FormatWIMXML)
	req := requestFor(t, file)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Inspect(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	req.Source.UpdateID = "different-source"
	if _, err := Inspect(context.Background(), req); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("source mismatch: %v", err)
	}
}
