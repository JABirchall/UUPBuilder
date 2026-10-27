package metadata

import (
	"context"
	"errors"
	"testing"
)

// Choosing the first package or dependent identity would discard contradictory
// semantic input. The parser must reject both singleton ambiguities.
func TestCBSSingletonContradictionsAreRejected(t *testing.T) {
	for _, tc := range []struct{ name, records string }{
		{"package-identifiers", `<package identifier="Synthetic.First" releaseType="Update"/><package identifier="Synthetic.Second" releaseType="Update"/>`},
		{"package-release-types", `<package identifier="Synthetic.Package" releaseType="Update"/><package identifier="Synthetic.Package" releaseType="Feature Pack"/>`},
		{"dependency-identities", `<dependency><dependentAssembly dependencyType="prerequisite"><assemblyIdentity name="Synthetic.FirstBase" version="10.0.1.1" processorArchitecture="arm64"/><assemblyIdentity name="Synthetic.SecondBase" version="10.0.1.1" processorArchitecture="arm64"/></dependentAssembly></dependency>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := inputFile(t, "opaque.xml", `<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="Synthetic.OS" version="10.0.1.2" processorArchitecture="arm64"/>`+tc.records+`</assembly>`, FormatCBSXML)
			if _, err := Inspect(context.Background(), requestFor(t, file)); !errors.Is(err, ErrConflictingMetadata) {
				t.Fatalf("want singleton conflict, got %v", err)
			}
		})
	}
}
