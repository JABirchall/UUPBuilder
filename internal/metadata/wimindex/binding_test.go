package wimindex

import (
	"context"
	"testing"
)

func TestMetadataBindingAndWitnessCountDoNotExposeIndex(t *testing.T) {
	m, fs, idx, _ := metadataInputs(t, nil)
	as, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, &syntheticCodec{})
	if err != nil {
		t.Fatal(err)
	}
	defer as[0].Close()
	r := as[0].Receipt()
	if !idx.MatchesMetadataReceipt(r) || idx.LookupCount(r.SHA1) != 1 || idx.LookupCount("missing") != 0 {
		t.Fatal("exact binding/count missing")
	}
	for _, change := range []func(*MetadataReceipt){
		func(r *MetadataReceipt) { r.Source.BuildLabel = "other" },
		func(r *MetadataReceipt) { r.ManifestDigest = "other" },
		func(r *MetadataReceipt) { r.IndexDigest = "other" },
		func(r *MetadataReceipt) { r.Payload.Provenance.Name = "other" },
		func(r *MetadataReceipt) { r.SourceSHA256 = "other" },
		func(r *MetadataReceipt) { r.Header.ImageCount++ },
		func(r *MetadataReceipt) { r.Entry.ImageIndex++ },
		func(r *MetadataReceipt) { r.Entry.Descriptor.Offset++ },
		func(r *MetadataReceipt) { r.SHA1 = "other" },
		func(r *MetadataReceipt) { r.SHA256 = "other" },
		func(r *MetadataReceipt) { r.Size++ },
		func(r *MetadataReceipt) { r.SourceRehashed = false },
	} {
		v := r
		change(&v)
		if idx.MatchesMetadataReceipt(v) {
			t.Fatal("false receipt binding accepted")
		}
	}
	w := idx.Lookup(r.SHA1)
	w[0].Entry = 0
	if idx.LookupCount(r.SHA1) != 1 || !idx.MatchesMetadataReceipt(r) || idx.Lookup(r.SHA1)[0].Entry == 0 {
		t.Fatal("read accessor mutates index")
	}
}
