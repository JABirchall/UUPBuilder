package isocontent

import "io"

func ValidateExpectations(e ISOExpectations) (map[string]ISOExpectedFile, error) {
	return validateISOExpectations(e)
}

// InspectEFIPE checks the source loader's PE architecture and EFI subsystem.
func InspectEFIPE(r io.ReaderAt, size int64, machine uint16) (uint16, error) {
	return inspectEFIPE(r, size, machine)
}

// InspectEFIFAT checks the source EFI image's FAT tree and embedded loader bytes.
func InspectEFIFAT(r io.ReaderAt, size int64, expected ISOExpectedFile, machine uint16) (uint16, error) {
	return inspectEFIFAT(r, size, expected, machine)
}
