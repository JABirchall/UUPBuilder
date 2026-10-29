package wimindex

import "encoding/hex"

// MatchesMetadataReceipt compares only immutable values, without serializing or
// cloning the index. An arbitrary receipt is not an artifact authority.
func (i *Index) MatchesMetadataReceipt(r MetadataReceipt) bool {
	if i == nil || i.digest == "" || r.IndexDigest != i.digest || r.Source != i.state.Source || r.ManifestDigest != i.state.ManifestDigest || !r.SourceRehashed || r.SHA1 != r.Entry.SHA1 || r.Size == 0 || r.Size != r.Entry.LogicalSize || len(r.SHA256) != 64 {
		return false
	}
	if b, err := hex.DecodeString(r.SHA256); err != nil || hex.EncodeToString(b) != r.SHA256 {
		return false
	}
	for _, c := range i.state.Containers {
		if c.Payload != r.Payload {
			continue
		}
		if !c.SourceRehashed || !c.MappingComplete || c.SourceSHA256 != r.SourceSHA256 || c.Header != r.Header {
			return false
		}
		for _, e := range c.Entries {
			if e.Ordinal == r.Entry.Ordinal {
				return e == r.Entry && e.Kind == "metadata" && e.Located && e.ImageIndex != 0 && e.References == 1 && (e.Descriptor.Flags == 2 || e.Descriptor.Flags == 6) && e.LogicalSize == e.Descriptor.Original
			}
		}
	}
	return false
}

// LookupCount allows a consumer to reserve a witness budget before Lookup copies.
func (i *Index) LookupCount(sha1 string) int {
	if i == nil {
		return 0
	}
	return len(i.witnesses[sha1])
}
