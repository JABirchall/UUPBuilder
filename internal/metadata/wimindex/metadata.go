package wimindex

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

var ErrUnsupported = errors.New("WIM metadata decoder implementation gap")

// Zero values select hard ceilings: 256 resources, 16384 chunks/resource,
// 64 MiB/resource, 256 MiB total output and resource reads, 1 MiB/chunk and
// 2 MiB of simultaneous caller chunk buffers. Source verification/index reads
// retain B1's separate fixed 64 KiB/50000-byte buffers and limits. Native codec
// internal memory is OS-managed, not covered by the caller-buffer ceiling.
type DecodeLimits struct {
	MaxResources, MaxChunks                       int
	MaxResourceBytes, MaxTotalBytes, MaxReadBytes uint64
	MaxChunkBytes, MaxBufferBytes                 int
}
type CodecIdentity struct {
	Name, SHA256 string
	Size         int64
}
type MetadataReceipt struct {
	Source                                    model.SourceIdentity
	ManifestDigest, IndexDigest, SourceSHA256 string
	Payload                                   model.PayloadIdentity
	Header                                    Header
	Entry                                     Entry
	SHA1, SHA256                              string
	Size                                      uint64
	SourceRehashed                            bool
	Codec                                     CodecIdentity
}

// MetadataArtifact owns private temporary decoded evidence. Only this type can
// publish a receipt after full original SHA1/size and final source rehash checks.
// The caller must Close it; no path, write handle or conversion capability is
// exposed. B3 can wrap it in io.NewSectionReader using Receipt().Size.
type MetadataArtifact struct {
	receipt MetadataReceipt
	mu      sync.RWMutex
	file    *os.File
	path    string
}

func (a *MetadataArtifact) Receipt() MetadataReceipt { return a.receipt }
func (a *MetadataArtifact) ReadAt(b []byte, off int64) (int, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file == nil {
		return 0, os.ErrClosed
	}
	if off < 0 {
		return 0, ErrInput
	}
	if len(b) == 0 {
		return 0, nil
	}
	if uint64(off) >= a.receipt.Size {
		return 0, io.EOF
	}
	if uint64(len(b)) > a.receipt.Size-uint64(off) {
		n, err := a.file.ReadAt(b[:a.receipt.Size-uint64(off)], off)
		if err == nil {
			err = io.EOF
		}
		return n, err
	}
	return a.file.ReadAt(b, off)
}
func (a *MetadataArtifact) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var err error
	if a.file != nil {
		err = a.file.Close()
		a.file = nil
	}
	if a.path != "" {
		removeErr := os.Remove(a.path)
		if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			a.path = ""
		} else {
			err = errors.Join(err, removeErr)
		}
	}
	return err
}

type metadataCodec interface {
	Decode(context.Context, []byte, int) ([]byte, error)
	Identity() CodecIdentity
	Close() error
}
type codecFactory func(context.Context) (metadataCodec, error)

func DecodeMetadata(ctx context.Context, manifest model.PayloadManifest, files []metadata.LocalResource, idx *Index, limits DecodeLimits) ([]*MetadataArtifact, error) {
	return decodeMetadata(ctx, manifest, files, idx, limits, systemMetadataCodec)
}
