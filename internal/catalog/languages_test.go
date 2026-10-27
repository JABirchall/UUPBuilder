package catalog

import (
	"context"
	"testing"
)

func TestLanguagesKeepSparseIdentifiersAndFallbackNames(t *testing.T) {
	s := serveJSON(t, []byte(`{"response":{"langList":{"0":"en-us","45":"sr-latn-rs","56":"future-lang"},"langFancyNames":{"en-us":"English"}}}`))
	langs, err := New(s.Client(), s.URL).Languages(context.Background(), sourceID)
	if err != nil || len(langs) != 3 || langs[1].ID != "sr-latn-rs" || langs[2].Name != "future-lang" {
		t.Fatalf("language IDs/names lost: %+v %v", langs, err)
	}
}

func TestLanguagesRejectDuplicateAndMissingCollections(t *testing.T) {
	for _, body := range []string{`{"response":{"langList":["en-us","en-us"]}}`, `{"response":{"langFancyNames":{}}}`} {
		s := serveJSON(t, []byte(body))
		if _, err := New(s.Client(), s.URL).Languages(context.Background(), sourceID); err == nil {
			t.Fatal("invalid language response accepted")
		}
	}
}
