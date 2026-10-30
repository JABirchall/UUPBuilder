package output

import (
	"bytes"
	"encoding/binary"
	"testing"
	"uupbuilder/internal/model"
)

func testWIM(edition string) []byte {
	x := []byte(`<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>9</ARCH><EDITIONID>` + edition + `</EDITIONID><LANGUAGES><LANGUAGE>en-GB</LANGUAGE></LANGUAGES></WINDOWS></IMAGE></WIM>`)
	b := make([]byte, 256+len(x))
	copy(b, "MSWIM\x00\x00\x00")
	binary.LittleEndian.PutUint32(b[8:], 208)
	binary.LittleEndian.PutUint32(b[12:], 0x10d00)
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint16(b[42:], 1)
	binary.LittleEndian.PutUint32(b[44:], 1)
	binary.LittleEndian.PutUint64(b[72:], uint64(len(x))|2<<56)
	binary.LittleEndian.PutUint64(b[80:], 256)
	binary.LittleEndian.PutUint64(b[88:], uint64(len(x)))
	copy(b[256:], x)
	return b
}
func TestInspectInternalImageReadsActualIdentity(t *testing.T) {
	b := testWIM("Professional")
	got, err := inspectImage(bytes.NewReader(b), int64(len(b)))
	if err != nil || len(got) != 1 || got[0].Edition != "Professional" || got[0].Architecture != model.ArchitectureAMD64 || got[0].Language != "en-GB" {
		t.Fatalf("actual XML identity: %+v %v", got, err)
	}
	binary.LittleEndian.PutUint64(b[80:], uint64(len(b)))
	if _, err := inspectImage(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("out-of-bounds WIM XML accepted")
	}
}

func TestInternalImageRejectsUnknownVersionAndSplitNames(t *testing.T) {
	b := testWIM("Professional")
	binary.LittleEndian.PutUint32(b[12:], 0x123456)
	if _, err := inspectImage(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("unknown image header version accepted")
	}
	for _, name := range []string{"install01.swm", "install02.swm", "install0.swm", "install-1.swm"} {
		if partNumber(name) != 0 {
			t.Fatalf("nonstandard Setup split filename accepted: %s", name)
		}
	}
}

func TestBootWIMRequiresActualBootIndexAndResource(t *testing.T) {
	b := testWIM("WindowsPE")
	if err := verifyBootHeader(bytes.NewReader(b), int64(len(b)), 1); err == nil {
		t.Fatal("boot WIM without selected boot index accepted")
	}
	binary.LittleEndian.PutUint32(b[120:], 1)
	binary.LittleEndian.PutUint64(b[96:], 16)
	binary.LittleEndian.PutUint64(b[104:], 208)
	if err := verifyBootHeader(bytes.NewReader(b), int64(len(b)), 1); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(b[104:], uint64(len(b)))
	if err := verifyBootHeader(bytes.NewReader(b), int64(len(b)), 1); err == nil {
		t.Fatal("boot metadata outside WIM accepted")
	}
}
