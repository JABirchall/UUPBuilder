package source

import (
	"fmt"
	"testing"
	"uupbuilder/internal/metadata/wimmeta"
)

func TestExpectedFactsRetainOSPathsAndRepresentativeLinkAndOpaqueRecords(t *testing.T) {
	s := wimmeta.Snapshot{Security: []wimmeta.Security{{Raw: []byte("descriptor")}}}
	for n := 0; n < 30; n++ {
		s.Entries = append(s.Entries, wimmeta.Entry{Path: fmt.Sprint("/early", n), HardlinkID: uint64(n + 1)})
	}
	s.Entries = append(s.Entries, wimmeta.Entry{Path: "/Windows/System32/ntoskrnl.exe"}, wimmeta.Entry{Path: "/Windows/System32/config/SOFTWARE"}, wimmeta.Entry{Path: "/Windows/System32/config/SYSTEM"}, wimmeta.Entry{Path: "/reparse", ReparseTag: 0xa0000003}, wimmeta.Entry{Path: "/opaque", Tags: []wimmeta.Tag{{Tag: 65535, Data: []byte{3, 4}}}}, wimmeta.Entry{Path: "/named", Streams: []wimmeta.Stream{{SHA1: "data"}, {Name: []uint16{'a'}, SHA1: "ads"}}})
	facts := expectedFacts(s)
	seen := map[string]bool{}
	for _, f := range facts {
		seen[f.Path] = true
	}
	for _, path := range []string{"/Windows/System32/ntoskrnl.exe", "/Windows/System32/config/SOFTWARE", "/Windows/System32/config/SYSTEM", "/reparse", "/opaque", "/named"} {
		if !seen[path] {
			t.Fatal("representative record crowded out", path)
		}
	}
}
