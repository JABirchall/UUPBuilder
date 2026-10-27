package probes

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"
)

func inspectCompDBCAB(body []byte, member string) (uint32, error) {
	fail := func() (uint32, error) {
		return 0, errors.New("CAB is outside the bounded one-folder/one-XML-member LZX observation variant")
	}
	if len(body) < 36 || string(body[:4]) != "MSCF" || body[24] != 3 || body[25] != 1 {
		return fail()
	}
	u16 := binary.LittleEndian.Uint16
	u32 := binary.LittleEndian.Uint32
	extent := uint64(u32(body[8:]))
	if extent < 36 || extent > uint64(len(body)) || u16(body[26:]) != 1 || u16(body[28:]) != 1 {
		return fail()
	}
	body = body[:int(extent)]
	flags := u16(body[30:])
	folderAt := uint64(36)
	reserveFolder, reserveData := uint64(0), uint64(0)
	if flags == 4 {
		if len(body) < 40 {
			return fail()
		}
		folderAt = 40 + uint64(u16(body[36:]))
		reserveFolder = uint64(body[38])
		reserveData = uint64(body[39])
	} else if flags != 0 {
		return fail()
	}
	if folderAt > extent || 8+reserveFolder > extent-folderAt {
		return fail()
	}
	folder := body[int(folderAt):]
	dataAt := uint64(u32(folder))
	blocks := u16(folder[4:])
	if blocks == 0 || blocks > 128 || u16(folder[6:]) != 0xf03 {
		return fail()
	}
	fileAt := uint64(u32(body[16:]))
	if fileAt < folderAt+8+reserveFolder || fileAt > extent || 16 > extent-fileAt {
		return fail()
	}
	file := body[int(fileAt):]
	size := u32(file)
	if size == 0 || size > 4<<20 || u32(file[4:]) != 0 || u16(file[8:]) != 0 {
		return fail()
	}
	if dataAt > extent || dataAt < fileAt+17 {
		return fail()
	}
	nameArea := body[int(fileAt+16):int(dataAt)]
	end := bytes.IndexByte(nameArea, 0)
	if end < 0 {
		return fail()
	}
	name := string(nameArea[:end])
	if !utf8.ValidString(name) || strings.ContainsAny(name, "/\\") || name != member {
		return fail()
	}
	for _, r := range name {
		if r > 127 {
			return fail()
		}
	}
	var total uint64
	for i := uint16(0); i < blocks; i++ {
		if dataAt > extent || 8+reserveData > extent-dataAt {
			return fail()
		}
		block := body[int(dataAt):]
		compressed, uncompressed := uint64(u16(block[4:])), uint64(u16(block[6:]))
		if compressed == 0 || uncompressed == 0 || uncompressed > 32768 {
			return fail()
		}
		step := 8 + reserveData + compressed
		if step > extent-dataAt {
			return fail()
		}
		dataAt += step
		total += uncompressed
		if total > 4<<20 {
			return fail()
		}
	}
	if total != uint64(size) {
		return fail()
	}
	return size, nil
}
