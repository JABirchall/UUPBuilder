package planner

import (
	"github.com/pelletier/go-toml/v2"
	"testing"
)

func TestLicenseBytesTOMLRoundTrip(t *testing.T) {
	for _, original := range []AppProvision{{LicenseXML: nil}, {LicenseXML: []byte{}}, {LicenseXML: []byte("<License>\r\ncontent\r\n</License>")}} {
		b, e := toml.Marshal(original)
		if e != nil {
			t.Fatal(e)
		}
		var decoded AppProvision
		if e = toml.Unmarshal(b, &decoded); e != nil {
			t.Fatal(e)
		}
		if string(original.LicenseXML) != string(decoded.LicenseXML) {
			t.Fatalf("license bytes changed: %q -> %q; encoded %s", original.LicenseXML, decoded.LicenseXML, b)
		}
		if hash(original) != hash(decoded) {
			t.Fatal("empty license changed frozen identity")
		}
	}
}
