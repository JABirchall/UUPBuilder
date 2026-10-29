package engine

import (
	"context"
	"errors"
	"io"
	"slices"
	"uupbuilder/internal/engine/source"
)

type SetupBootReceipt struct {
	Source                                                  source.SetupBootDescriptor
	Archive                                                 Receipt
	RecordsVerified, Complete, NativeFilesystemPreservation bool
}

// SetupBootArtifact owns only the actual source-bound transformed WIM bytes.
// Its receipt deliberately leaves operational Setup/native acceptance false.
type SetupBootArtifact struct {
	archive *Artifact
	source  source.SetupBootDescriptor
	recipe  *source.BoundSetupBoot
}

func (a *SetupBootArtifact) Receipt() SetupBootReceipt {
	if a == nil || a.archive == nil {
		return SetupBootReceipt{}
	}
	d := a.source
	d.Media.ReservedPaths = slices.Clone(d.Media.ReservedPaths)
	return SetupBootReceipt{Source: d, Archive: a.archive.Receipt(), RecordsVerified: true}
}
func (a *SetupBootArtifact) ReadAt(b []byte, off int64) (int, error) {
	if a == nil || a.archive == nil {
		return 0, ErrInput
	}
	return a.archive.ReadAt(b, off)
}
func (a *SetupBootArtifact) Close() error {
	if a == nil || a.archive == nil {
		return nil
	}
	return a.archive.Close()
}

// BuildSetupBoot writes the fixed single-image boot framing and inspects all
// transformed records through the retained output, after independent complete
// resource/table/XML verification. It grants no NormalizedSource/ReadyPlan.
func BuildSetupBoot(ctx context.Context, r *source.BoundSetupBoot, limits Limits) (result *SetupBootArtifact, runErr error) {
	if ctx == nil || r == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := bounds(limits)
	if e != nil {
		return nil, e
	}
	if e = r.CheckLive(); e != nil {
		return nil, e
	}
	d := r.Descriptor()
	if d.Resources < 1 || d.Resources > l.MaxResources || d.XMLBytes > uint64(l.MaxXMLBytes) || d.AccountedBytes+uint64(d.Resources)*1024+d.XMLBytes*8+4096 > l.MaxResultBytes {
		return nil, ErrLimit
	}
	in := writeInput{XML: r.XML(), HeaderFlags: r.HeaderFlags(), Boot: true, RecipeDigest: d.RuleDigest, ProofDigest: d.ProofDigest, CheckLive: r.CheckLive, Resources: make([]inputResource, 0, d.Resources)}
	for i := 0; i < d.Resources; i++ {
		id, a, e := r.Resource(i)
		if e != nil {
			return nil, e
		}
		in.Resources = append(in.Resources, inputResource{SHA1: id.SHA1, SHA256: id.SHA256, Size: id.Size, References: id.References, Metadata: i == 0, Reader: a})
	}
	// The independent record walk rereads fixed headers/names as well as spans.
	// Charge its bounded worst read cost in addition to writer/verifier custody.
	inspectBudget := d.MetadataBytes * 2
	if inspectBudget >= l.MaxReadBytes {
		return nil, ErrLimit
	}
	l.MaxReadBytes -= inspectBudget
	a, e := writeStandard(ctx, in, l)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			runErr = errors.Join(runErr, a.Close())
		}
	}()
	meta := a.receipt.Resources[0]
	if e = r.InspectMetadata(ctx, io.NewSectionReader(a, int64(meta.Offset), int64(meta.Size)), meta.Size); e != nil {
		return nil, e
	}
	if e = r.CheckLive(); e != nil {
		return nil, e
	}
	// Bind the fixed identity only after the original PE and current Setup rule
	// have been validated by the live typed producer, never from output XML.
	a.expected = ImageInformation{1, "0", "WindowsPE", "WindowsPE", "10.0.19041.1"}
	result = &SetupBootArtifact{archive: a, source: d, recipe: r}
	ok = true
	return result, nil
}
