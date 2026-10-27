package model

import "testing"

func TestRelativePathRejectsPaddedDeviceNames(t *testing.T) {
	for _, value := range []string{"NUL .txt", "dir/COM1 .bin", "conout$ .log"} {
		if got, err := ValidateRelativePath(value); err == nil {
			t.Errorf("padded device name %q accepted as %q", value, got)
		}
	}
}

func TestRelativePathRejectsTraversalUNCADSAndDevices(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../a", `a\..\b`, "/absolute", `C:\file`, `C:relative`, `\\server\share\file`, `\\?\C:\file`, "a:stream", "a\x00b", "NUL", "con.txt", "dir/COM1.bin", "LPT9", "COM¹.txt", "CONIN$", "a/", "a//b", "a/./b", "trailing.", "trailing ", "a?b", "a\nb"} {
		t.Run(value, func(t *testing.T) {
			if got, err := ValidateRelativePath(value); err == nil {
				t.Fatalf("unsafe path %q accepted as %q", value, got)
			}
		})
	}
	for _, tc := range []struct{ input, want string }{{`sources\install.esd`, "sources/install.esd"}, {"语言/日本語.esd", "语言/日本語.esd"}, {"COM10.txt", "COM10.txt"}, {"folder with spaces/file.esd", "folder with spaces/file.esd"}} {
		got, err := ValidateRelativePath(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
}
