package jobstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	platform "uupbuilder/internal/platform/windows"
)

var ErrPredecessorLimit = errors.New("predecessor read allowance exceeded")

// PredecessorReader is subordinate to its live tx/Store/Workspace and Begin/open
// contexts. The allowance charges ancestry verification plus returned bytes.
// Each tx permits64 live borrowers (the current source-container ceiling);
// each pins at most256 files/64 ancestry
// levels. Reads use64KiB steps. No historical file-ID seal or stage authority.
type PredecessorReader struct {
	tx        *Transaction
	ctx       context.Context
	pins      []*platform.ReadPin
	selected  *platform.ReadPin
	remaining uint64
	stops     []func() bool
	closed    bool
	closeErr  error
}

func (tx *Transaction) readUsable(ctx context.Context) error {
	if ctx == nil || tx.readContext == nil {
		return errors.New("live predecessor contexts required")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := tx.readContext.Err(); e != nil {
		return e
	}
	return tx.usable()
}

// OpenPredecessor accepts exact identities, not adoption text. Current semantic
// bytes/ancestry are revalidated under nonfollow pins. Equal bytes replaced
// before acquisition may satisfy the checkpoint; live identity is then retained.
func (tx *Transaction) OpenPredecessor(ctx context.Context, p PredecessorIdentity, out OutputIdentity, allowance uint64) (result *PredecessorReader, resultErr error) {
	if tx == nil || tx.store == nil {
		return nil, os.ErrClosed
	}
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := tx.readUsable(ctx); e != nil {
		return nil, e
	}
	if allowance == 0 || len(tx.readers) >= 64 {
		return nil, ErrPredecessorLimit
	}
	if e := validateOutput(out); e != nil {
		return nil, e
	}
	idx := s.stageIndex(tx.id)
	if idx < 0 || s.state.Stages[idx].Committed || !reflect.DeepEqual(s.state.Stages[idx].Intent, tx.intent) {
		return nil, errors.New("predecessor borrower lacks exact durable intent")
	}
	if !containsPredecessor(tx.intent.Predecessors, p) {
		return nil, errors.New("predecessor not declared by active transaction")
	}
	if e := s.validateJournal(s.state); e != nil {
		return nil, e
	}
	target := -1
	for j, c := range s.state.Checkpoints {
		if c.Checkpoint.Intent.StageID == p.StageID && c.Checkpoint.Digest == p.Digest {
			for _, o := range c.Checkpoint.Outputs {
				if o == out {
					target = j
				}
			}
		}
	}
	if target < 0 {
		return nil, errors.New("exact committed predecessor output missing")
	}
	r := &PredecessorReader{tx: tx, ctx: ctx, remaining: allowance}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, r.closeLocked())
		}
	}()
	heights := map[int]int{}
	byPath := map[string]*platform.ReadPin{}
	var buf [64 << 10]byte
	var bind func(int, int) error
	bind = func(j, depth int) error {
		if depth >= 64 {
			return ErrPredecessorLimit
		}
		// Count checkpoint nodes, including this one. Reusing verified pins must
		// still charge the cached subtree's longest path at the caller's depth.
		if height := heights[j]; height != 0 {
			if height > 64-depth {
				return ErrPredecessorLimit
			}
			return nil
		}
		height := 1
		c := s.state.Checkpoints[j].Checkpoint
		if c.Intent.JobID != tx.intent.JobID || c.Intent.PlanDigest != tx.intent.PlanDigest || c.Intent.ConfigDigest != tx.intent.ConfigDigest {
			return errors.New("foreign predecessor job/plan/config")
		}
		for _, ancestor := range c.Intent.Predecessors {
			found := -1
			for k := j - 1; k >= 0; k-- {
				a := s.state.Checkpoints[k].Checkpoint
				if a.Intent.StageID == ancestor.StageID && a.Digest == ancestor.Digest {
					found = k
					break
				}
			}
			if found < 0 {
				return errors.New("predecessor ancestry missing")
			}
			if e := bind(found, depth+1); e != nil {
				return e
			}
			height = max(height, 1+heights[found])
		}
		for _, o := range c.Outputs {
			if len(r.pins) >= 256 || uint64(o.Size) > r.remaining {
				return ErrPredecessorLimit
			}
			pin, e := s.w.OpenReadPin(o.Path)
			if e != nil {
				return e
			}
			r.pins = append(r.pins, pin)
			byPath[o.Path] = pin
			if pin.Size() != o.Size {
				return errors.New("predecessor size changed")
			}
			h := sha256.New()
			for off := int64(0); off < o.Size; {
				if e = s.interrupt("predecessor-before-verify"); e != nil {
					return e
				}
				if e = tx.readUsable(ctx); e != nil {
					return e
				}
				want := min(int64(len(buf)), o.Size-off)
				n, readErr := pin.ReadAt(buf[:int(want)], off)
				r.remaining -= uint64(n)
				if readErr != nil || int64(n) != want {
					return errors.Join(readErr, io.ErrUnexpectedEOF)
				}
				h.Write(buf[:n])
				off += int64(n)
			}
			if hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
				return errors.New("predecessor SHA256 changed")
			}
		}
		heights[j] = height
		return nil
	}
	if e := bind(target, 0); e != nil {
		return nil, e
	}
	r.selected = byPath[out.Path]
	if e := r.checkLocked(true); e != nil {
		return nil, e
	}
	if tx.readers == nil {
		tx.readers = map[*PredecessorReader]struct{}{}
	}
	tx.readers[r] = struct{}{}
	r.stops = []func() bool{context.AfterFunc(ctx, func() { r.Close() }), context.AfterFunc(tx.readContext, func() { r.Close() })}
	return r, nil
}
func containsPredecessor(list []PredecessorIdentity, p PredecessorIdentity) bool {
	for _, known := range list {
		if known == p {
			return true
		}
	}
	return false
}
func (r *PredecessorReader) checkLocked(pins bool) error {
	if e := r.tx.readUsable(r.ctx); e != nil {
		return e
	}
	if r.closed {
		return os.ErrClosed
	}
	if pins {
		for _, pin := range r.pins {
			if e := pin.Check(); e != nil {
				return e
			}
		}
	}
	return nil
}
func (r *PredecessorReader) ReadAt(b []byte, off int64) (total int, resultErr error) {
	if r == nil || r.tx == nil {
		return 0, os.ErrClosed
	}
	s := r.tx.store
	for {
		s.mu.Lock()
		e := r.checkLocked(total == 0)
		if e == nil && off < 0 {
			e = errors.New("negative predecessor offset")
		}
		if e != nil {
			s.mu.Unlock()
			return total, e
		}
		if total == len(b) {
			s.mu.Unlock()
			return total, nil
		}
		if off >= r.selected.Size() {
			s.mu.Unlock()
			return total, io.EOF
		}
		want := int(min(int64(len(b)-total), int64(64<<10), r.selected.Size()-off))
		if uint64(want) > r.remaining {
			s.mu.Unlock()
			return total, ErrPredecessorLimit
		}
		n, readErr := r.selected.ReadAt(b[total:total+want], off)
		readErr = errors.Join(readErr, s.interrupt("predecessor-after-read"))
		r.remaining -= uint64(n)
		total += n
		off += int64(n)
		e = errors.Join(readErr, r.checkLocked(total == len(b)))
		s.mu.Unlock()
		if e != nil {
			return total, e
		}
		if n != want {
			return total, io.ErrUnexpectedEOF
		}
		if total == len(b) {
			return total, nil
		}
	}
}
func (r *PredecessorReader) closeLocked() error {
	if !r.closed {
		r.closed = true
		for _, stop := range r.stops {
			stop()
		}
		for j := len(r.pins) - 1; j >= 0; j-- {
			r.closeErr = errors.Join(r.closeErr, r.pins[j].Close())
		}
		r.pins = nil
		delete(r.tx.readers, r)
	}
	return r.closeErr
}
func (r *PredecessorReader) Close() error {
	if r == nil || r.tx == nil || r.tx.store == nil {
		return nil
	}
	s := r.tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	return r.closeLocked()
}
func (tx *Transaction) closePredecessors() error {
	var e error
	for r := range tx.readers {
		e = errors.Join(e, r.closeLocked())
	}
	return e
}
