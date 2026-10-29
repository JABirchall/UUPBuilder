package windows

import "encoding/binary"

// FILE_ID_BOTH_DIR_INFO (winbase.h): signed byte ShortNameLength at 68,
// padding byte at 69, WCHAR ShortName[12] at 70. Count is bytes, not a NUL
// termination contract. Preserve raw code units, including malformed UTF-16,
// so comparison can never invent or silently normalize a source name.
func directoryShortName(record []byte) ([]uint16, error) {
	if len(record) < 94 {
		return nil, ErrTreePreserved
	}
	n := int(int8(record[68]))
	if n < 0 || n > 24 || n%2 != 0 {
		return nil, ErrTreePreserved
	}
	u := make([]uint16, n/2)
	for j := range u {
		u[j] = binary.LittleEndian.Uint16(record[70+j*2:])
	}
	return u, nil
}
