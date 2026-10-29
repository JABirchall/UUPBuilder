package source

// Gaps keeps other source families visible. It does not filter catalog targets.
func Gaps() []string {
	return []string{"canonical-other-generations: source-specific reconstruction and native proof required", "express-psf: delta reconstruction provider required", "edition-reference: derivation and reference recipe required", "full-media: independent media-layout proof required", "update-only: upstream media-role inspection required", "unknown-future: format and source-role inspection required"}
}
