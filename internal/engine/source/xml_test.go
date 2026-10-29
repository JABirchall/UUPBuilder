package source

import (
	"bytes"
	"testing"
)

func TestSelectedXMLCarriesUnknownFieldsAndChangesOnlyImageFraming(t *testing.T) {
	text := []byte(`<WIM><IMAGE INDEX="2"><NAME>PE</NAME></IMAGE><IMAGE INDEX="7"><NAME>Original</NAME><OPAQUE a="b">unknown</OPAQUE><WINDOWS><VERSION><BUILD>19041</BUILD></VERSION></WINDOWS></IMAGE></WIM>`)
	got, e := oneImage(text, 7)
	want := []byte(`<IMAGE INDEX="1"><NAME>Original</NAME><OPAQUE a="b">unknown</OPAQUE><WINDOWS><VERSION><BUILD>19041</BUILD></VERSION></WINDOWS></IMAGE>`)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal(string(got), e)
	}
	if _, e = oneImage(text, 3); e == nil {
		t.Fatal("missing image guessed")
	}
	if _, e = decodeXML([]byte{0, 0xd8}); e == nil {
		t.Fatal("invalid UTF16 replaced")
	}
	if got, e := oneImage([]byte(`<WIM xmlns:p="urn:opaque"><IMAGE INDEX="1"><p:OPAQUE>carry</p:OPAQUE></IMAGE></WIM>`), 1); e == nil {
		t.Fatal("dropped outer namespace dependency", string(got))
	}
}
