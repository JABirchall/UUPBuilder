package cabindex

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
)

type fingerprint struct {
	sha256 string
	size   uint64
}
type memberSink struct {
	ctx               context.Context
	store             *privateStore
	source            sourceWork
	limits            Limits
	state             *Snapshot
	refs              map[string]int
	seen              map[string]fingerprint
	artifacts         *[]*ContentArtifact
	pending           *int
	file              *os.File
	name              string
	h1, h256          hash.Hash
	written, observed uint64
	next, matches     int
}

func (s *memberSink) begin(n int) (uintptr, error) {
	if e := s.ctx.Err(); e != nil {
		return 0, e
	}
	if s.file != nil || n != s.next || n >= len(s.source.table.Members) {
		return 0, ErrIntegrity
	}
	m := s.source.table.Members[n]
	if m.Size > s.limits.MaxDiskBytes-s.state.RetainedBytes {
		return 0, ErrLimit
	}
	f, name, e := s.store.create()
	if e != nil {
		return 0, e
	}
	s.file, s.name = f, name
	s.written = 0
	s.h1 = sha1.New()
	s.h256 = sha256.New()
	return uintptr(n + 2), nil
}
func (s *memberSink) write(h uintptr, b []byte) (int, error) {
	if e := s.ctx.Err(); e != nil {
		return 0, e
	}
	if s.file == nil || h != uintptr(s.next+2) {
		return 0, ErrIntegrity
	}
	m := s.source.table.Members[s.next]
	if len(b) > s.limits.MaxBufferBytes || uint64(len(b)) > m.Size-s.written || uint64(len(b)) > s.limits.MaxDeclaredBytes-s.state.ObservedBytes {
		return 0, ErrLimit
	}
	n, e := s.file.Write(b)
	s.written += uint64(n)
	s.observed += uint64(n)
	s.state.ObservedBytes += uint64(n)
	s.h1.Write(b[:n])
	s.h256.Write(b[:n])
	if n != len(b) {
		e = errors.Join(e, io.ErrShortWrite)
	}
	return n, e
}
func (s *memberSink) end(h uintptr) (runErr error) {
	if s.file == nil || h != uintptr(s.next+2) {
		return ErrIntegrity
	}
	m := s.source.table.Members[s.next]
	if s.written != m.Size {
		return ErrIntegrity
	}
	if e := s.ctx.Err(); e != nil {
		return e
	}
	name := s.name
	e := errors.Join(s.file.Sync(), s.file.Close())
	s.file = nil
	if e != nil {
		return e
	}
	w := Witness{Payload: s.source.resource.Identity, SourceSHA256: s.source.sha, Ordinal: s.next + 1, Member: m, SHA1: hex.EncodeToString(s.h1.Sum(nil)), SHA256: hex.EncodeToString(s.h256.Sum(nil)), Size: s.written, SizeProvenance: "cab-member-bytes"}
	a, e := s.store.retain(name, w)
	if e != nil {
		return e
	}
	a.binding = s.state.Oracle
	keep := false
	defer func() {
		if !keep {
			runErr = errors.Join(runErr, a.close(), s.store.remove(name))
		}
	}()
	if e := a.verify(s.ctx, w, s.limits.MaxBufferBytes); e != nil {
		return e
	}
	if old, ok := s.seen[w.SHA1]; ok && (old.sha256 != w.SHA256 || old.size != w.Size) {
		return ErrIntegrity
	}
	s.seen[w.SHA1] = fingerprint{w.SHA256, w.Size}
	nested := false
	if w.Size >= 4 {
		var b [4]byte
		if _, e := a.ReadAt(b[:], 0); e != nil {
			return e
		}
		nested = string(b[:]) == "MSCF"
	}
	if nested {
		s.state.Gaps = append(s.state.Gaps, Gap{w.Payload, w.Ordinal, "nested-cabinet-not-decoded"})
	}
	index, needed := s.refs[w.SHA1]
	if needed && s.state.References[index].Original.SizeKnown && s.state.References[index].Original.Size != w.Size {
		return ErrIntegrity
	}
	if needed && s.state.References[index].Original.Witnesses == 0 && !nested {
		identityBytes := len(w.Payload.Provenance.Source) + len(w.Payload.Provenance.Name) + len(w.Payload.Digest.Value) + len(w.Payload.Digest.Algorithm) + len(w.Member.Name)
		charge := 2048 + uint64(identityBytes)*8
		if len(s.state.Witnesses) >= s.limits.MaxWitnesses || charge > s.limits.MaxResultBytes-s.state.AccountedBytes {
			return ErrLimit
		}
		s.state.AccountedBytes += charge
		r := &s.state.References[index]
		if len(r.Witnesses) == 0 {
			*s.pending--
		}
		r.Witnesses = append(r.Witnesses, len(s.state.Witnesses))
		r.CABSize = w.Size
		r.CABSizeKnown = true
		r.Ambiguous = len(r.Witnesses) > 1
		s.state.Witnesses = append(s.state.Witnesses, w)
		*s.artifacts = append(*s.artifacts, a)
		s.state.RetainedBytes += w.Size
		s.matches++
		keep = true
	}
	s.next++
	s.name = ""
	return nil
}
func (s *memberSink) abort() error {
	var e error
	if s.file != nil {
		e = s.file.Close()
		s.file = nil
	}
	return e
}
func (s *memberSink) complete() error {
	if s.file != nil || s.next != len(s.source.table.Members) {
		return ErrIntegrity
	}
	return s.ctx.Err()
}
