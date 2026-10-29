package wimmeta

import "slices"

// RecordCounts is historical scalar evidence. It does not assert parent liveness.
type RecordCounts struct{ Entries, Security, Gaps, MaxStringBytes int }

func (o *Oracle) RecordCounts() RecordCounts {
	if !o.Claim().Verified {
		return RecordCounts{}
	}
	c := RecordCounts{Entries: len(o.state.Entries), Security: len(o.state.Security), Gaps: len(o.state.Gaps)}
	// Scan immutable lengths only; no Snapshot, serialization or variable copy.
	for _, e := range o.state.Entries {
		c.MaxStringBytes = max(c.MaxStringBytes, len(e.Path), len(e.Name)*2, len(e.ShortName)*2, len(e.PathUTF16)*2)
		for _, s := range e.Streams {
			c.MaxStringBytes = max(c.MaxStringBytes, len(s.Name)*2)
		}
	}
	return c
}

// EntryAt charges conservative record/slice/string storage before copying any
// nested values. Zero is an exhausted allowance, never a default sentinel.
func (o *Oracle) EntryAt(n int, allowance uint64) (Entry, uint64, error) {
	if !o.Claim().Verified || n < 0 || n >= len(o.state.Entries) {
		return Entry{}, 0, ErrInput
	}
	e := o.state.Entries[n]
	cost := uint64(1024 + len(e.Path)*2 + (len(e.Name)+len(e.ShortName)+len(e.PathUTF16))*4 + len(e.Padding)*2)
	for _, s := range e.Streams {
		cost += uint64(512 + len(s.Name)*4 + len(s.Padding)*2 + (len(s.SHA1)+len(s.Kind)+len(s.SizeProvenance))*2)
	}
	for _, t := range e.Tags {
		cost += uint64(128 + (len(t.Data)+len(t.Padding))*2)
	}
	if cost > allowance {
		return Entry{}, 0, ErrLimit
	}
	e.Name, e.ShortName, e.PathUTF16, e.Padding = slices.Clone(e.Name), slices.Clone(e.ShortName), slices.Clone(e.PathUTF16), slices.Clone(e.Padding)
	e.Streams = slices.Clone(e.Streams)
	for j := range e.Streams {
		e.Streams[j].Name = slices.Clone(e.Streams[j].Name)
		e.Streams[j].Padding = slices.Clone(e.Streams[j].Padding)
	}
	e.Tags = slices.Clone(e.Tags)
	for j := range e.Tags {
		e.Tags[j].Data = slices.Clone(e.Tags[j].Data)
		e.Tags[j].Padding = slices.Clone(e.Tags[j].Padding)
	}
	return e, cost, nil
}

func (o *Oracle) SecurityAt(n int, allowance uint64) (Security, uint64, error) {
	if !o.Claim().Verified || n < 0 || n >= len(o.state.Security) {
		return Security{}, 0, ErrInput
	}
	s := o.state.Security[n]
	cost := uint64(256 + (len(s.Raw)+len(s.Owner.Raw)+len(s.Group.Raw))*2)
	for _, a := range []*ACL{s.DACL, s.SACL} {
		if a != nil {
			cost += 128
			for _, e := range a.ACEs {
				cost += uint64(256 + len(e.SID.Raw)*2)
			}
		}
	}
	if cost > allowance {
		return Security{}, 0, ErrLimit
	}
	s.Raw, s.Owner.Raw, s.Group.Raw = slices.Clone(s.Raw), slices.Clone(s.Owner.Raw), slices.Clone(s.Group.Raw)
	s.DACL, s.SACL = cloneACL(s.DACL), cloneACL(s.SACL)
	return s, cost, nil
}

func (o *Oracle) GapAt(n int, allowance uint64) (Gap, uint64, error) {
	if !o.Claim().Verified || n < 0 || n >= len(o.state.Gaps) {
		return Gap{}, 0, ErrInput
	}
	g := o.state.Gaps[n]
	cost := uint64(512 + (len(g.Kind)+len(g.Detail))*2)
	if cost > allowance {
		return Gap{}, 0, ErrLimit
	}
	return g, cost, nil // Strings are immutable values; no borrowed mutable slice.
}
