// Package engine contains the bounded reconstruction prerequisite. It does not
// mint a Toolchain, NormalizedSource, transaction receipt, or assembly success.
package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"sync"
	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/metadata/privatestore"
)

var ErrInput = errors.New("unbound WIM reconstruction input")
var ErrIntegrity = errors.New("WIM reconstruction integrity changed")
var ErrLimit = errors.New("WIM reconstruction bound exceeded")

// Public zero values select ceilings; positive values may only lower them.
// Result accounting excludes caller-owned producers and the Go/OS heaps.
type Limits struct {
	MaxResources, MaxXMLBytes, MaxBufferBytes    int
	MaxOutputBytes, MaxReadBytes, MaxResultBytes uint64
}

func bounds(l Limits) (Limits, error) {
	for i, p := range []*int{&l.MaxResources, &l.MaxXMLBytes, &l.MaxBufferBytes} {
		cap := []int{524288, 1 << 20, 64 << 10}[i]
		if *p < 0 || *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for i, p := range []*uint64{&l.MaxOutputBytes, &l.MaxReadBytes, &l.MaxResultBytes} {
		cap := []uint64{8 << 30, 64 << 30, 512 << 20}[i]
		if *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}

type Resource struct {
	SHA1, SHA256 string
	Offset, Size uint64
	References   uint32
	Metadata     bool
}
type Receipt struct {
	RecipeDigest, ProofDigest, SHA256                              string
	Size, LookupOffset, XMLOffset, ReadBytes                       uint64
	Resources                                                      []Resource
	BytesVerified, WindowsCompatible, NativeFilesystemPreservation bool
}
type Artifact struct {
	mu          sync.RWMutex
	store       *privatestore.Store
	file        *privatestore.File
	name        string
	receipt     Receipt
	expected    ImageInformation
	boundRecipe *source.BoundRecipe
	closed      bool
	closeErr    error
}

func (a *Artifact) Receipt() Receipt {
	s := a.receipt
	s.Resources = slices.Clone(s.Resources)
	return s
}
func (a *Artifact) ReadAt(b []byte, off int64) (int, error) {
	if a == nil {
		return 0, ErrInput
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return 0, os.ErrClosed
	}
	if a.file == nil {
		return 0, ErrInput
	}
	return a.file.ReadAt(b, off)
}
func (a *Artifact) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.closed = true
		if a.store != nil {
			a.closeErr = a.store.Close()
		}
	}
	return a.closeErr
}

// Reconstruct borrows live source capabilities and owns only generated private
// output. The result is a byte-verified component, never a production stage.
func Reconstruct(ctx context.Context, r *source.BoundRecipe, l Limits) (*Artifact, error) {
	if ctx == nil || r == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	limits, e := bounds(l)
	if e != nil {
		return nil, e
	}
	d := r.Descriptor()
	if d.Resources < 1 || d.Resources > limits.MaxResources || d.XMLBytes > uint64(limits.MaxXMLBytes) || uint64(d.Resources)*1024+d.XMLBytes*8+4096 > limits.MaxResultBytes {
		return nil, ErrLimit
	}
	in := writeInput{XML: r.XML(), HeaderFlags: r.HeaderFlags(), RecipeDigest: d.RecipeDigest, ProofDigest: d.ProofDigest, CheckLive: r.CheckLive, Resources: make([]inputResource, 0, d.Resources)}
	// The recipe's bounded immutable resource list needs only value copies here.
	for n := 0; n < d.Resources; n++ {
		id, reader, e := r.Resource(n)
		if e != nil {
			return nil, e
		}
		in.Resources = append(in.Resources, inputResource{SHA1: id.SHA1, SHA256: id.SHA256, Size: id.Size, References: id.References, Metadata: n == 0, Reader: reader})
	}
	expected, e := expectedImage(d)
	if e != nil {
		return nil, e
	}
	a, e := writeStandard(ctx, in, l)
	if e != nil {
		return nil, e
	}
	a.expected = expected
	a.boundRecipe = r
	return a, nil
}
func expectedImage(d source.Descriptor) (ImageInformation, error) {
	if d.Recipe.Source.Architecture != "x86" || d.Recipe.Edition != "Professional" || d.Recipe.BaselineVersion != "10.0.19041.1" {
		return ImageInformation{}, ErrInput
	}
	return ImageInformation{1, "0", d.Recipe.Edition, "Client", d.Recipe.BaselineVersion}, nil
}

type inputResource struct {
	SHA1, SHA256 string
	Size         uint64
	References   uint32
	Metadata     bool
	Reader       io.ReaderAt
}
type writeInput struct {
	XML                       []byte
	Resources                 []inputResource
	HeaderFlags               uint32
	RecipeDigest, ProofDigest string
	CheckLive                 func() error
	Boot                      bool
}
