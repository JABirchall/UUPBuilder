package engine

// Fixed selected-source test preparation only. These types are absent from the
// product executable and cannot construct a Toolchain, ReadyPlan or live proof.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	platform "uupbuilder/internal/platform/windows"
)

type fixedDiskFootprint struct {
	SourceRetained, DecodedContent, Metadata, CAB, Archive              uint64
	NativeDestination, NativeCache, Evidence, RetainedHeadroom, Reserve uint64
	Total                                                               uint64
	// Native allocation, NTFS overhead and OS-selected DISM log/scratch have no
	// enforced quota. These allowances are estimates, never a native write cap.
	NativeCostsKnown bool
}

func checkedPreparationSum(values ...uint64) (uint64, error) {
	var n uint64
	for _, v := range values {
		if v > ^uint64(0)-n {
			return 0, ErrLimit
		}
		n += v
	}
	return n, nil
}
func fixedPreparationFootprint(source uint64) (fixedDiskFootprint, error) {
	f := fixedDiskFootprint{SourceRetained: source, DecodedContent: 8 << 30, Metadata: 256 << 20, CAB: 2 << 30, Archive: 8 << 30, NativeDestination: 64 << 30, NativeCache: 8 << 30, Evidence: 2 << 30, RetainedHeadroom: 16 << 30, Reserve: 8 << 30}
	// Both input classes retain their existing total-source ceilings. This is
	// declared metadata, not a fresh measurement or permission to replay bytes.
	if source == 0 || source > 10<<30 {
		return f, ErrLimit
	}
	var e error
	f.Total, e = checkedPreparationSum(f.SourceRetained, f.DecodedContent, f.Metadata, f.CAB, f.Archive, f.NativeDestination, f.NativeCache, f.Evidence, f.RetainedHeadroom, f.Reserve)
	return f, e
}
func (f fixedDiskFootprint) Check(v platform.StorageVolume) error {
	if f.Total == 0 || v.ID == "" || v.AvailableBytes < f.Total {
		return ErrLimit
	}
	return nil
}
func (f fixedDiskFootprint) CheckChanged(before, after platform.StorageVolume) error {
	if before.ID == "" || after.ID != before.ID {
		return platform.ErrPreparationCustody
	}
	return f.Check(after)
}

const fixedEvidenceQuota = uint64(16 << 20)
const fixedBlobQuota = uint64((1 << 30) + (8 << 20))

type fixedPreparationEvidence struct {
	mu                     sync.Mutex
	parent                 *platform.PinnedWorkspace
	file                   *os.File
	finalFile              *os.File
	limit, used, blobBytes uint64
	failure                error
	final, closed          bool
}

func newFixedPreparationEvidence(p *platform.PinnedWorkspace, limit uint64) (*fixedPreparationEvidence, error) {
	if p == nil || limit == 0 || limit > fixedEvidenceQuota {
		return nil, ErrLimit
	}
	f, e := p.CreateEvidenceFile("attempt.jsonl")
	if e != nil {
		return nil, e
	}
	final, e := p.CreateEvidenceFile("final.json")
	if e != nil {
		return nil, errors.Join(e, f.Close())
	}
	return &fixedPreparationEvidence{parent: p, file: f, finalFile: final, limit: limit}, nil
}
func (s *fixedPreparationEvidence) Record(kind string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	if s.failure != nil {
		return s.failure
	}
	if len(kind) == 0 || len(kind) > 64 {
		return ErrInput
	}
	b, e := json.Marshal(struct {
		Kind  string `json:"kind"`
		Value any    `json:"value"`
	}{kind, value})
	if e == nil && (uint64(len(b))+1 > s.limit-s.used || len(b) > 1<<20) {
		e = ErrLimit
	}
	if e != nil {
		s.failure = e
		return e
	}
	b = append(b, '\n')
	n, e := s.file.Write(b)
	s.used += uint64(n)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	e = errors.Join(e, s.file.Sync())
	if e != nil {
		s.failure = e
	}
	return e
}

// Final has a separate exclusive file and 1 MiB reserve even when the event
// quota or event writer failed. Neither failed attempts nor final data reopen.
func (s *fixedPreparationEvidence) Final(value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.final {
		return os.ErrClosed
	}
	s.final = true
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return ErrLimit
	}
	f := s.finalFile
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return errors.Join(e, f.Sync())
}

type fixedBlobIdentity struct {
	Name, SHA256 string
	Size         uint64
}

func (s *fixedPreparationEvidence) Blob(name string, data []byte) (fixedBlobIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := fixedBlobIdentity{Name: name}
	if s.closed {
		return v, os.ErrClosed
	}
	if name != "comparison.json" && name != "observer.json" && name != "native.json" {
		return v, ErrInput
	}
	if uint64(len(data)) > 512<<20 || uint64(len(data)) > fixedBlobQuota-s.blobBytes {
		return v, ErrLimit
	}
	if name == "native.json" && len(data) > 8<<20 {
		return v, ErrLimit
	}
	f, e := s.parent.CreateEvidenceFile(name)
	if e != nil {
		return v, e
	}
	n, e := f.Write(data)
	s.blobBytes += uint64(n)
	v.Size = uint64(n)
	if e == nil && n != len(data) {
		e = io.ErrShortWrite
	}
	h := sha256.Sum256(data[:n])
	v.SHA256 = hex.EncodeToString(h[:])
	return v, errors.Join(e, f.Sync(), f.Close())
}
func (s *fixedPreparationEvidence) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.file.Sync(), s.finalFile.Sync(), s.file.Close(), s.finalFile.Close())
}

func fixedPreparationContext(parent context.Context, deadline time.Time, cancelSignal <-chan struct{}) (context.Context, context.CancelFunc, error) {
	now := time.Now()
	if parent == nil || deadline.IsZero() || !deadline.After(now) || deadline.Sub(now) > 24*time.Hour {
		return nil, nil, ErrInput
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	if cancelSignal != nil {
		go func() {
			select {
			case <-cancelSignal:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel, nil
}

type fixedStorageWatch struct {
	Path, VolumeID string
	Reserve        uint64
}

func watchFixedPreparationStorage(parent context.Context, volumes []fixedStorageWatch) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			for _, expected := range volumes {
				v, e := platform.InspectStorage(expected.Path)
				if e != nil {
					cancel(e)
					return
				}
				if v.ID != expected.VolumeID {
					cancel(platform.ErrPreparationCustody)
					return
				}
				if v.AvailableBytes < expected.Reserve {
					cancel(ErrLimit)
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return ctx, func() { cancel(context.Canceled) }
}

type fixedSourceDiskCost struct {
	Entries                                                         int
	LogicalBytes, StreamAllocationEstimate, MetadataEstimate, Total uint64
}

func fixedSourceDiskEstimate(x *SourceExpectations) (fixedSourceDiskCost, error) {
	var v fixedSourceDiskCost
	if x == nil {
		return v, ErrInput
	}
	if e := x.CheckLive(); e != nil {
		return v, e
	}
	v.Entries = len(x.entries)
	// Conservative per-name logical expansion (including hardlink aliases),
	// 64 KiB rounded stream allocation and 64 KiB metadata per entry are
	// estimates. This is not an NTFS/provider physical-allocation guarantee.
	v.MetadataEstimate = uint64(v.Entries) * (64 << 10)
	for _, entry := range x.entries {
		for _, content := range entry.Content {
			var e error
			v.LogicalBytes, e = checkedPreparationSum(v.LogicalBytes, content.Size)
			if e != nil {
				return v, e
			}
			rounded, e := checkedPreparationSum(content.Size, (64<<10)-1)
			if e != nil {
				return v, e
			}
			rounded = rounded / (64 << 10) * (64 << 10)
			v.StreamAllocationEstimate, e = checkedPreparationSum(v.StreamAllocationEstimate, rounded)
			if e != nil {
				return v, e
			}
		}
	}
	var e error
	v.Total, e = checkedPreparationSum(v.StreamAllocationEstimate, v.MetadataEstimate)
	if e != nil || v.Total > 64<<30 {
		return v, ErrLimit
	}
	return v, nil
}
