package probes

import (
	"encoding/binary"
	"testing"
)

// This synthetic CAB header is not decodable compression data. Only its
// declared member/folder/block extents are used by bounded preflight tests.
func syntheticCAB() []byte {
	name := []byte("member.xml\x00")
	dataOffset := 44 + 16 + len(name)
	b := make([]byte, dataOffset+9)
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], 44)
	b[24] = 3
	b[25] = 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], 1)
	binary.LittleEndian.PutUint32(b[36:], uint32(dataOffset))
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint16(b[42:], 0xf03)
	binary.LittleEndian.PutUint32(b[44:], 3)
	copy(b[60:], name)
	binary.LittleEndian.PutUint16(b[dataOffset+4:], 1)
	binary.LittleEndian.PutUint16(b[dataOffset+6:], 3)
	b[dataOffset+8] = 'x'
	return b
}

func TestCABPreflightBoundsSelectedMemberBeforeExecution(t *testing.T) {
	b := syntheticCAB()
	size, err := inspectCompDBCAB(b, "member.xml")
	if err != nil || size != 3 {
		t.Fatalf("declared CAB member=%d err=%v", size, err)
	}
	for _, name := range []string{"truncated", "file count", "oversize output", "other member", "unsafe member", "block size", "folder outside cabinet", "split folder"} {
		t.Run(name, func(t *testing.T) {
			b := syntheticCAB()
			member := "member.xml"
			switch name {
			case "truncated":
				b = b[:40]
			case "file count":
				b[28] = 2
			case "oversize output":
				binary.LittleEndian.PutUint32(b[44:], (4<<20)+1)
			case "other member":
				member = "different.xml"
			case "unsafe member":
				copy(b[60:], []byte("../bad.xml\x00"))
			case "block size":
				b[len(b)-3] = 4
			case "folder outside cabinet":
				binary.LittleEndian.PutUint32(b[36:], ^uint32(0))
			case "split folder":
				binary.LittleEndian.PutUint16(b[52:], 0xffff)
			}
			if _, err := inspectCompDBCAB(b, member); err == nil {
				t.Fatal("unbounded/mismatched CAB member accepted before launch")
			}
		})
	}
}
