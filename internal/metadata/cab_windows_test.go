package metadata

import (
	"context"
	"os"
	"testing"
)

func TestReadCABExtractsOnlyRequestedMetadata(t *testing.T) {
	ownedParent := t.TempDir()
	t.Setenv("TMP", ownedParent)
	t.Setenv("TEMP", ownedParent)
	docs, err := ReadCABMetadata(context.Background(), testCAB("metadata.xml", []byte("<safe/>")), []string{"metadata.xml"})
	if err != nil {
		t.Fatal(err)
	}
	if string(docs["metadata.xml"]) != "<safe/>" || len(docs) != 1 {
		t.Fatalf("wrong extraction: %v", docs)
	}
	if _, err = ReadCABMetadata(context.Background(), testCAB("metadata.xml", []byte("<safe/>")), []string{"not-offered.xml"}); err == nil {
		t.Fatal("unadvertised extraction request accepted")
	}
	entries, err := os.ReadDir(ownedParent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("current owned metadata scope was not removed: %v entries=%v", err, entries)
	}
}
