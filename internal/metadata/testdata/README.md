# Metadata fixture provenance

The Microsoft AppX and Windows App SDK XML files are public, Microsoft-authored
source test/sample data from pinned commits, under the accompanying repository
MIT notices. They are authentic source examples, **not captured UUP inbox apps**,
production licenses, validated provisioning inputs, or real source-family proof.
The provenance JSON files record exact original paths, URLs, commits, lengths and
SHA-256 values; their acquisition inventories may also list files not shipped here.
Only public sample identifiers, manifests, test license data and public keys are
included. No download locators, credentials or private material are included.

`m1-professional-factual-projection.json` is a newly authored factual projection
of a locally inspected Microsoft 22000.1 ARM64 CompDB, with original provenance.
It is not an upstream XML fixture and cannot prove that the parser understands
the real document, or that any real image roles/edition bases/app phases work.
The raw Microsoft UUP CompDB is deliberately not redistributed here because its
redistribution rights have not been established.

Inline fixtures in the Go tests are explicitly synthetic. Their provider reports
exercise binding/contradiction rules but do not attest any real source family.

Schema context: Microsoft AppX Identity and PackageDependency references:
https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-identity
https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-packagedependency
Microsoft package identity overview:
https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/package-identity-overview

CompDB schema 1.2 support is based on direct local observation of the original
source metadata, not a published Microsoft schema guarantee. PayloadHash remains
opaque: its base64 width and consumer variable names do not prove an algorithm.
CBS asm.v3 and WIM XML currently have synthetic contract tests, without authentic
redistributable CBS/WIM corpus evidence. WIM WindowsPE cannot by itself distinguish
setup from recovery. No provider/helper execution is part of these tests.

Primary WIM field/architecture context (not a copied implementation):
https://github.com/microsoft/go-winio/blob/main/wim/wim.go
https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
CBS assembly identity/dependency context:
https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests
That application-manifest reference is not a complete CBS servicing schema;
CBS servicing prerequisites remain unproved and are not a source-family pass.
