package engine

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"unicode/utf16"

	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

// sourceNativeObservation is private, source-derived observation only. Neither
// this wrapper nor any data/JSON it returns authenticates an imaging invocation
// or mints ObservedSourceContractResult/creator/deletion/assembly authority.
// The future executor must bind its real return separately after review.
type sourceNativeObservation struct {
	mu       sync.Mutex
	expected *SourceExpectations
	claim    *jobstore.DirectoryClaim
	session  *platform.NativeObservationSession
	id       platform.TreeIdentity
	profile  platform.NativeObservationLimits
	closed   bool
	closeErr error
}

func newSourceNativeObservation(ctx context.Context, x *SourceExpectations, c *jobstore.DirectoryClaim, limits platform.NativeObservationLimits) (*sourceNativeObservation, error) {
	if ctx == nil || c == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := x.CheckLive(); e != nil {
		return nil, e
	}
	if e := c.CheckLive(ctx); e != nil {
		return nil, e
	}
	id := c.Tree().Identity()
	if id.SourceDigest != x.state.ProofDigest || c.SourceDigest() != x.state.ProofDigest {
		return nil, ErrInput
	}
	l, e := platform.NativeObservationProfile(limits)
	if e != nil {
		return nil, e
	}
	if len(x.entries) > l.MaxEntries {
		return nil, platform.ErrTreeLimit
	}
	// Derive shape before allocating the descriptor table or any nested names.
	var cost uint64 = 4096
	for _, en := range x.entries {
		if len(en.Original.Path) > 4096 || len(en.Original.Streams) > 256 {
			return nil, platform.ErrTreeLimit
		}
		n := uint64(512 + len(en.Original.Path)*4 + len(en.Original.Streams)*128)
		for _, stream := range en.Original.Streams {
			if len(stream.Name) > 512 {
				return nil, platform.ErrTreeLimit
			}
			n += uint64(len(stream.Name)) * 8
		}
		if n > l.MaxResultBytes-min(cost, l.MaxResultBytes) {
			return nil, platform.ErrTreeLimit
		}
		cost += n
	}
	paths := make([]platform.NativeObservationPath, 0, len(x.entries))
	for _, en := range x.entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		o := en.Original
		if !o.PathValid {
			return nil, ErrInput
		}
		name := strings.TrimPrefix(o.Path, "/")
		if name == "" {
			name = "."
		}
		p := platform.NativeObservationPath{Path: name, Directory: o.Attributes&16 != 0, Reparse: o.Attributes&0x400 != 0}
		for _, stream := range o.Streams {
			switch stream.Kind {
			case "data":
				p.DefaultSize = stream.Size
			case "named-data":
				name := string(utf16.Decode(stream.Name))
				if !slices.Equal(stream.Name, utf16.Encode([]rune(name))) {
					return nil, ErrInput
				}
				p.Streams = append(p.Streams, platform.NativeObservationStream{Name: name, Size: stream.Size})
			case "directory-placeholder", "unused-main", "reparse":
			default:
				return nil, ErrInput
			}
		}
		paths = append(paths, p)
	}
	b, e := platform.PreflightNativeObservation(paths, l)
	if e != nil {
		return nil, e
	}
	// Retain enough allowance for the temporary source-derived table while
	// the session copies its immutable inspection descriptors.
	if cost > l.MaxResultBytes-b.AccountedBytes {
		return nil, platform.ErrTreeLimit
	}
	s, e := platform.BorrowNativeObservation(ctx, c.Tree(), paths, l)
	if e != nil {
		return nil, e
	}
	w := &sourceNativeObservation{expected: x, claim: c, session: s, id: id, profile: l}
	if e = w.live(ctx); e != nil {
		return w, errors.Join(e, w.Close())
	}
	return w, nil
}

func (s *sourceNativeObservation) live(ctx context.Context) error {
	if s == nil || ctx == nil || s.expected == nil || s.claim == nil || s.session == nil {
		return ErrInput
	}
	if s.closed {
		return os.ErrClosed
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.expected.CheckLive(); e != nil {
		return e
	}
	if e := s.claim.CheckLive(ctx); e != nil {
		return e
	}
	if s.claim.Tree().Identity() != s.id || s.session.Identity() != s.id || s.id.SourceDigest != s.expected.state.ProofDigest {
		return ErrInput
	}
	return s.session.CheckObservationLive(ctx)
}
func (s *sourceNativeObservation) Identity() platform.TreeIdentity {
	if s == nil {
		return platform.TreeIdentity{}
	}
	return s.id
}
func (s *sourceNativeObservation) CheckObservationLive(ctx context.Context) error {
	if s == nil {
		return ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live(ctx)
}
func (s *sourceNativeObservation) ObserveInventory(ctx context.Context, l platform.TreeLimits) (platform.TreeInventory, error) {
	if s == nil {
		return platform.TreeInventory{}, ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(ctx); e != nil {
		return platform.TreeInventory{}, e
	}
	v, e := s.session.ObserveInventory(ctx, l)
	return v, errors.Join(e, s.live(ctx))
}
func (s *sourceNativeObservation) Observe(ctx context.Context, name string, l platform.MetadataLimits) (platform.MetadataObservation, error) {
	if s == nil {
		return platform.MetadataObservation{}, ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(ctx); e != nil {
		return platform.MetadataObservation{}, e
	}
	v, e := s.session.Observe(ctx, name, l)
	return v, errors.Join(e, s.live(ctx))
}
func (s *sourceNativeObservation) ReadOwnedAt(ctx context.Context, name, stream string, b []byte, off int64) (int, error) {
	if s == nil {
		return 0, ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(ctx); e != nil {
		return 0, e
	}
	n, e := s.session.ReadOwnedAt(ctx, name, stream, b, off)
	return n, errors.Join(e, s.live(ctx))
}
func (s *sourceNativeObservation) beginMetadataPass(ctx context.Context) error {
	if s == nil {
		return ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(ctx); e != nil {
		return e
	}
	e := s.session.BeginMetadataPass(ctx)
	return errors.Join(e, s.live(ctx))
}
func (s *sourceNativeObservation) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.closeErr = s.session.Close()
	}
	return s.closeErr
}
