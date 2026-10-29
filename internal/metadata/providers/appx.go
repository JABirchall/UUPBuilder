package providers

import (
	"archive/zip"
	"context"
	"io"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type Appx struct{}

// Appx observes a single package manifest. Bundle expansion and blockmap/signature
// validation are separate missing operations; XML observations cannot authorize
// provisioning or establish licenses, package selection or installability.
func (Appx) Inspect(ctx context.Context, r metadata.LocalResource, limits metadata.Limits) (metadata.ProviderResult, error) {
	var out metadata.ProviderResult
	limit, err := documentLimit(limits)
	if err != nil {
		return out, err
	}
	f, err := verified(ctx, r)
	if err != nil {
		return out, err
	}
	defer f.Close()
	z, err := zip.NewReader(f, r.Identity.Size)
	if err != nil {
		return out, metadata.ErrMalformedMetadata
	}
	if len(z.File) > 4096 {
		return out, metadata.ErrLimit
	}
	seen := map[string]bool{}
	var manifest *zip.File
	for _, entry := range z.File {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		name := strings.TrimSuffix(entry.Name, "/")
		normal, err := model.ValidateRelativePath(name)
		key := strings.ToLower(name)
		if err != nil || normal != name || seen[key] || (!entry.Mode().IsRegular() && !entry.FileInfo().IsDir()) {
			return out, metadata.ErrMalformedMetadata
		}
		seen[key] = true
		if key == "appxmetadata/appxbundlemanifest.xml" {
			return out, ErrUnsupported
		}
		if key == "appxmanifest.xml" {
			if !entry.Mode().IsRegular() {
				return out, metadata.ErrMalformedMetadata
			}
			manifest = entry
		}
	}
	if manifest == nil {
		return out, metadata.ErrMalformedMetadata
	}
	if manifest.UncompressedSize64 > uint64(limit) {
		return out, metadata.ErrLimit
	}
	reader, err := manifest.Open()
	if err != nil {
		return out, metadata.ErrMalformedMetadata
	}
	body, readErr := io.ReadAll(contextReader{ctx, io.LimitReader(reader, limit+1)})
	closeErr := reader.Close()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if readErr != nil || closeErr != nil || uint64(len(body)) != manifest.UncompressedSize64 {
		return out, metadata.ErrIntegrity
	}
	if int64(len(body)) > limit {
		return out, metadata.ErrLimit
	}
	out.Documents = []metadata.MetadataDocument{{Resource: metadata.ResourceReference{Payload: r.Identity, Member: manifest.Name}, Format: metadata.FormatAppxXML, Original: body, Provenance: "uupbuilder:appx-zip-manifest-v1"}}
	return out, nil
}
