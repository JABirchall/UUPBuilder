package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// This profile is separate from OwnedTree's fixture creation/cleanup profile.
// Zero selects ceilings at this constructor only; internal residuals never do.
type NativeObservationLimits struct {
	MaxEntries, MaxDepth, MaxStreams, MaxHandles int
	MaxReadBytes, MaxResultBytes, MaxExportBytes uint64
}

type NativeObservationStream struct {
	Name string
	Size uint64
}

// Descriptors are only inspection allowlists. They carry no native-attempt,
// creator, descendant ownership, deletion, or successful comparison authority.
type NativeObservationPath struct {
	Path               string
	Directory, Reparse bool
	DefaultSize        uint64
	Streams            []NativeObservationStream
}

type NativeObservationBudget struct {
	Entries, Streams, Handles                                                       int
	ExpectedReadBytes, AccountedBytes                                               uint64
	ExpectedExportBytes                                                             uint64
	ContentBytes, MetadataCapacityBytes, DirectoryCapacityBytes, IdentityQueryBytes uint64
	ValidationCalls, ValidationAllowanceBytes                                       uint64
}

// NativeObservationProfile validates and fixes lowerable limits without I/O.
func NativeObservationProfile(l NativeObservationLimits) (NativeObservationLimits, error) {
	return nativeObservationBounds(l)
}

func nativeObservationBounds(l NativeObservationLimits) (NativeObservationLimits, error) {
	for j, p := range []*int{&l.MaxEntries, &l.MaxDepth, &l.MaxStreams, &l.MaxHandles} {
		cap := []int{262144, 32, 524288, 262144}[j]
		if *p < 0 || *p > cap {
			return l, ErrTreeLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for j, p := range []*uint64{&l.MaxReadBytes, &l.MaxResultBytes, &l.MaxExportBytes} {
		cap := []uint64{64 << 30, 512 << 20, 512 << 20}[j]
		if *p > cap {
			return l, ErrTreeLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}

const nativeRootValidationScratch = uint64(64 << 10)

// Includes metadata result/scratch and the query buffer held through return.
// The final identity/root recheck additionally needs its own validation scratch.
func nativeMetadataScratch(l MetadataLimits) uint64 {
	return uint64(l.MaxBufferBytes)*12 + uint64(l.MaxStreams+l.MaxEAs)*128 + 8192 + (64 << 10)
}

// PreflightNativeObservation charges the original bounded descriptor shape
// before maps/copies/opens. It plans two metadata/inventory passes and one
// complete per-name content read. DirectoryCapacityBytes is a nominal two
// queries per directory per pass; extra pages still spend the runtime budget.
// Query fields count requested buffer/copy capacities, not reported disk I/O.
func PreflightNativeObservation(paths []NativeObservationPath, limits NativeObservationLimits) (b NativeObservationBudget, err error) {
	l, e := nativeObservationBounds(limits)
	if e != nil {
		return b, e
	}
	if len(paths) == 0 || len(paths) > l.MaxEntries {
		return b, fmt.Errorf("%w: source entry count", ErrTreeLimit)
	}
	b.Entries = len(paths)
	if l.MaxResultBytes < 144<<10 || l.MaxExportBytes < 8192 {
		return b, ErrTreeLimit
	}
	b.AccountedBytes = 16 << 10
	b.ExpectedExportBytes = 8192
	b.ValidationCalls = 5
	for _, p := range paths {
		if len(p.Path) > 4096 || len(p.Streams) > 256 {
			return b, ErrTreeLimit
		}
		if p.Path != "." {
			if n, e := treeName(p.Path, l.MaxDepth); e != nil || n != p.Path {
				return b, errors.Join(ErrTreePreserved, e)
			}
			for _, component := range strings.Split(p.Path, "/") {
				if len(utf16.Encode([]rune(component))) > 255 {
					return b, ErrTreeLimit
				}
			}
		}
		if p.Directory && p.DefaultSize != 0 || p.Reparse && (p.DefaultSize != 0 || len(p.Streams) != 0) {
			return b, ErrTreePreserved
		}
		b.Handles++
		// Include copied descriptors, map keys, handles, identity/error records,
		// and two returned inventory rows; query buffers are scratch below.
		cost := uint64(2048 + len(p.Path)*12 + len(p.Streams)*256)
		if cost > l.MaxResultBytes-min(b.AccountedBytes, l.MaxResultBytes) {
			return b, fmt.Errorf("%w: source result shape", ErrTreeLimit)
		}
		b.AccountedBytes += cost
		depth := strings.Count(p.Path, "/") + 1
		if p.Path == "." {
			depth = 0
		}
		b.MetadataCapacityBytes += 2 * (4*(64<<10) + 64 + 128)
		if p.Reparse {
			b.MetadataCapacityBytes += 2 * 16384
		}
		b.ValidationCalls += 8
		b.IdentityQueryBytes += uint64(4 * depth * 128)
		if p.Path != "." {
			b.IdentityQueryBytes += 2 * 128
		}
		if p.Directory {
			b.DirectoryCapacityBytes += 4 * (64 << 10)
			b.ValidationCalls += 2
			b.IdentityQueryBytes += uint64(2*128 + 2*depth*128)
		}
		b.Streams++
		if len(p.Streams) >= 256 {
			return b, ErrTreeLimit
		}
		b.ExpectedExportBytes += uint64(512 + len(p.Path)*4 + len(p.Streams)*128)
		content := func(size uint64) error {
			if size > l.MaxReadBytes-min(b.ContentBytes, l.MaxReadBytes) {
				return ErrTreeLimit
			}
			b.ContentBytes += size
			chunks := (size + 65535) / 65536
			b.ValidationCalls += chunks * 4
			b.IdentityQueryBytes += chunks * uint64(128+2*depth*128)
			return nil
		}
		if e := content(p.DefaultSize); e != nil {
			return b, e
		}
		for _, stream := range p.Streams {
			if len(stream.Name) > 1024 {
				return b, ErrTreeLimit
			}
			if len(utf16.Encode([]rune(stream.Name))) > 255 {
				return b, ErrTreeLimit
			}
			b.ExpectedExportBytes += uint64(len(stream.Name)) * 4
			if n, e := safeStreamName(":" + stream.Name + ":$DATA"); e != nil || n == "" || n != stream.Name {
				return b, errors.Join(ErrTreePreserved, e)
			}
			cost = uint64(512 + len(stream.Name)*8)
			if cost > l.MaxResultBytes-b.AccountedBytes {
				return b, ErrTreeLimit
			}
			b.AccountedBytes += cost
			if e := content(stream.Size); e != nil {
				return b, e
			}
			b.Streams++
			b.Handles++
		}
		b.ValidationAllowanceBytes = b.ValidationCalls * 8192
		b.ExpectedReadBytes = b.ContentBytes + b.MetadataCapacityBytes + b.DirectoryCapacityBytes + b.IdentityQueryBytes + b.ValidationAllowanceBytes
		if b.ExpectedReadBytes > l.MaxReadBytes {
			return b, fmt.Errorf("%w: source expected query/content work", ErrTreeLimit)
		}
	}
	// Root ancestry is added by Borrow. Fixed metadata scratch remains live
	// through the final root/owner recheck, so both must fit beside retained data.
	b.Handles += 2
	plannedScratch := nativeMetadataScratch(MetadataLimits{MaxBufferBytes: 64 << 10, MaxStreams: 256, MaxEAs: 256}) + nativeRootValidationScratch
	if b.Streams > l.MaxStreams || b.Handles > l.MaxHandles || b.AccountedBytes > l.MaxResultBytes || plannedScratch > l.MaxResultBytes-b.AccountedBytes || b.ExpectedExportBytes > l.MaxExportBytes {
		return b, ErrTreeLimit
	}
	return b, nil
}

type nativeObservedEntry struct {
	file          *os.File
	id            FileIdentity
	parent, leaf  string
	short         []uint16
	shortObserved bool
	streams       map[string]*os.File
	name          string
	streamOrder   []string
}

// NativeObservationSession owns only read-only observer handles. It borrows
// the original root/parents; it never inserts entries into the fixture ledger.
// All observations are sequential, non-atomic evidence, not deletion authority.
type NativeObservationSession struct {
	mu                                  sync.Mutex
	root                                *OwnedTree
	id                                  TreeIdentity
	limits                              NativeObservationLimits
	expected                            map[string]NativeObservationPath
	entries                             map[string]*nativeObservedEntry
	read, accounted, scratch            uint64
	handles, baseHandles, streamRecords int
	closed, incomplete                  bool
	closeErr, errorState                error
	// Private native port for deterministic known-ID/query failure tests.
	info                                            func(*os.File) (windows.ByHandleFileInformation, error)
	queryDirectory                                  func(windows.Handle, uint32, []byte) error
	closeFile                                       func(*os.File) error
	failures                                        []NativeObservationFailure
	order                                           []*nativeObservedEntry
	budget                                          NativeObservationBudget
	contentRead, queryCapacity, validationAllowance uint64
	failureEvidenceExhausted                        bool
	terminalFailure                                 NativeObservationFailure
	terminalCause                                   error
}

type NativeObservationFailure struct {
	Path       string
	Identity   FileIdentity
	NativeCode uint32
	Detail     string
}
type NativeObservedIdentity struct {
	Path      string
	Identity  FileIdentity
	Streams   []string
	ShortName []uint16
}
type NativeSessionEvidence struct {
	Tree                                                           TreeIdentity
	Limits                                                         NativeObservationLimits
	Entries                                                        []NativeObservedIdentity
	Failures                                                       []NativeObservationFailure
	ReadBytes, AccountedBytes                                      uint64
	RetainedHandles                                                int
	Closed, Incomplete, Preserved                                  bool
	Preflight                                                      NativeObservationBudget
	ContentReadBytes, QueryCapacityBytes, ValidationAllowanceBytes uint64
	ActualQueryReadBytesKnown                                      bool
	FailureEvidenceExhausted                                       bool
	TerminalFailure                                                NativeObservationFailure
}

func BorrowNativeObservation(ctx context.Context, root *OwnedTree, paths []NativeObservationPath, limits NativeObservationLimits) (*NativeObservationSession, error) {
	if ctx == nil || root == nil {
		return nil, ErrTreePreserved
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := nativeObservationBounds(limits)
	if e != nil {
		return nil, e
	}
	b, e := PreflightNativeObservation(paths, l)
	if e != nil {
		return nil, e
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	// No created-entry ledger may be silently reinterpreted as native output.
	if len(root.entries) != 0 {
		return nil, ErrTreePreserved
	}
	base := len(root.parents) + 1
	if b.Handles+len(root.parents) > l.MaxHandles {
		return nil, fmt.Errorf("%w: retained root/parent handles", ErrTreeLimit)
	}
	validationExtra := b.ValidationCalls * uint64(len(root.parents)) * 64
	if validationExtra > l.MaxReadBytes-b.ExpectedReadBytes {
		return nil, fmt.Errorf("%w: source root/owner validation allowance", ErrTreeLimit)
	}
	b.ExpectedReadBytes += validationExtra
	b.ValidationAllowanceBytes += validationExtra
	s := &NativeObservationSession{root: root, id: root.identity, limits: l, expected: make(map[string]NativeObservationPath, len(paths)), entries: make(map[string]*nativeObservedEntry, len(paths)), accounted: b.AccountedBytes, handles: base, baseHandles: base, info: nativeInfo, closeFile: func(f *os.File) error { return f.Close() }, queryDirectory: func(h windows.Handle, c uint32, b []byte) error {
		return windows.GetFileInformationByHandleEx(h, c, &b[0], uint32(len(b)))
	}}
	s.budget = b
	if e = s.validateRoot(); e != nil {
		return nil, e
	}
	keys := make(map[string]bool, len(paths))
	for _, p := range paths {
		key := strings.ToLower(p.Path)
		if keys[key] {
			return nil, ErrTreePreserved
		}
		keys[key] = true
		p.Streams = slices.Clone(p.Streams)
		seen := make(map[string]bool, len(p.Streams))
		for _, v := range p.Streams {
			k := strings.ToLower(v.Name)
			if seen[k] {
				return nil, ErrTreePreserved
			}
			seen[k] = true
		}
		s.expected[p.Path] = p
	}
	r, ok := s.expected["."]
	if !ok || !r.Directory || r.Reparse {
		return nil, ErrTreePreserved
	}
	for name := range s.expected {
		for parent := path.Dir(name); name != "."; parent = path.Dir(parent) {
			p, ok := s.expected[parent]
			if !ok || !p.Directory || p.Reparse {
				return nil, ErrTreePreserved
			}
			if parent == "." {
				break
			}
		}
	}
	s.entries["."] = &nativeObservedEntry{file: root.root, id: root.identity.Root, parent: ".", leaf: path.Base(root.identity.RelativePath), streams: map[string]*os.File{}}
	return s, nil
}

func (s *NativeObservationSession) Identity() TreeIdentity {
	if s == nil {
		return TreeIdentity{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}
func (s *NativeObservationSession) live(ctx context.Context) error {
	if ctx == nil {
		return ErrTreePreserved
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.closed {
		return os.ErrClosed
	}
	if s.root.identity != s.id {
		return ErrTreePreserved
	}
	if len(s.root.entries) != 0 {
		return ErrTreePreserved
	}
	return s.validateRoot()
}

// Root validation temporarily holds a workspace root plus owner marker, then
// rechecks the original root. Both slots, marker reads and query scratch count.
func (s *NativeObservationSession) validateRoot() error {
	if s.handles > s.limits.MaxHandles || 2 > s.limits.MaxHandles-s.handles {
		return ErrTreeLimit
	}
	if e := s.reserve(uint64(8192+len(s.root.parents)*64), 0, nativeRootValidationScratch); e != nil {
		return e
	}
	s.validationAllowance += uint64(8192 + len(s.root.parents)*64)
	s.handles += 2
	defer func() { s.handles -= 2; s.scratch -= nativeRootValidationScratch }()
	return s.root.validate()
}
func (s *NativeObservationSession) CheckObservationLive(ctx context.Context) error {
	if s == nil {
		return ErrTreePreserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root.mu.Lock()
	defer s.root.mu.Unlock()
	return s.live(ctx)
}

func (s *NativeObservationSession) reserve(read, result, scratch uint64) error {
	if read > s.limits.MaxReadBytes-s.read || result > s.limits.MaxResultBytes-s.accounted || scratch > s.limits.MaxResultBytes-s.accounted-result || s.scratch > s.limits.MaxResultBytes-s.accounted-result-scratch {
		s.incomplete = true
		return ErrTreeLimit
	}
	s.read += read
	s.accounted += result
	s.scratch += scratch
	return nil
}
func (s *NativeObservationSession) retainHandle() error {
	if s.handles >= s.limits.MaxHandles {
		s.incomplete = true
		return ErrTreeLimit
	}
	s.handles++
	return nil
}
func (s *NativeObservationSession) latch(e error) {
	if e != nil {
		s.incomplete = true
		if s.errorState == nil {
			s.errorState = e
		}
	}
}

func (s *NativeObservationSession) recordFailure(name string, id FileIdentity, e error) bool {
	if e == nil {
		return true
	}
	s.latch(e)
	f := fieldError(e)
	if len(f.Detail) > 2048 {
		f.Detail = f.Detail[:2048]
	}
	if err := s.reserve(0, uint64(512+(len(name)+len(f.Detail))*4), 0); err != nil {
		// A fixed emergency slot is included in the initial 16 KiB reservation.
		// Keep the first unavailable failure's exact known ID and native cause;
		// later failures cannot allocate an unbounded error chain on exhaustion.
		if !s.failureEvidenceExhausted {
			s.terminalFailure = NativeObservationFailure{Path: name, Identity: id, NativeCode: f.NativeCode, Detail: f.Detail}
			s.terminalCause = e
		}
		s.failureEvidenceExhausted = true
		return false
	}
	s.failures = append(s.failures, NativeObservationFailure{Path: name, Identity: id, NativeCode: f.NativeCode, Detail: f.Detail})
	return true
}

// Evidence returns bounded historical observer data, including after Close.
// Its Closed/Preserved fields never authorize reopening, cleanup or admission.
func (s *NativeObservationSession) Evidence(ctx context.Context, allowance uint64) (NativeSessionEvidence, error) {
	if s == nil || ctx == nil {
		return NativeSessionEvidence{}, ErrTreePreserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return NativeSessionEvidence{}, e
	}
	cost := uint64(8192 + len(s.failures)*256)
	for name, v := range s.entries {
		cost += uint64(512 + len(name)*4 + len(v.short)*4 + len(v.streams)*128)
		for n := range v.streams {
			cost += uint64(len(n)) * 4
		}
	}
	for _, f := range s.failures {
		cost += uint64(len(f.Path)+len(f.Detail)) * 4
	}
	cost += uint64(len(s.terminalFailure.Path)+len(s.terminalFailure.Detail)) * 4
	if allowance > s.limits.MaxExportBytes || cost > allowance {
		return NativeSessionEvidence{}, ErrTreeLimit
	}
	v := NativeSessionEvidence{Tree: s.id, Limits: s.limits, Failures: slices.Clone(s.failures), ReadBytes: s.read, AccountedBytes: s.accounted, RetainedHandles: s.handles, Closed: s.closed, Incomplete: s.incomplete, Preserved: true, Preflight: s.budget, ContentReadBytes: s.contentRead, QueryCapacityBytes: s.queryCapacity, ValidationAllowanceBytes: s.validationAllowance, FailureEvidenceExhausted: s.failureEvidenceExhausted, TerminalFailure: s.terminalFailure}
	for name, entry := range s.entries {
		row := NativeObservedIdentity{Path: name, Identity: entry.id, ShortName: slices.Clone(entry.short)}
		for stream := range entry.streams {
			row.Streams = append(row.Streams, stream)
		}
		sort.Strings(row.Streams)
		v.Entries = append(v.Entries, row)
	}
	sort.Slice(v.Entries, func(i, j int) bool { return v.Entries[i].Path < v.Entries[j].Path })
	if e := ctx.Err(); e != nil {
		return NativeSessionEvidence{}, e
	}
	return v, nil
}

// checkEntry reopens one exact component through its retained original parent.
// It never follows a reparse ancestor. Temporary opens count against the cap.
func (s *NativeObservationSession) checkEntry(name string) error {
	v := s.entries[name]
	if v == nil {
		return ErrTreePreserved
	}
	if name == "." {
		return s.validateRoot()
	}
	if e := s.checkEntry(v.parent); e != nil {
		return e
	}
	p := s.entries[v.parent]
	if e := s.reserve(128, 0, 4096); e != nil {
		return e
	}
	s.queryCapacity += 128
	defer func() { s.scratch -= 4096 }()
	if e := s.retainHandle(); e != nil {
		return e
	}
	defer func() { s.handles-- }()
	f, e := nativeTreeOpen(windows.Handle(p.file.Fd()), v.leaf, windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, windows.FILE_OPEN_FOR_BACKUP_INTENT, nil)
	if e != nil {
		return e
	}
	i, e := s.info(f)
	e = errors.Join(e, s.closeFile(f))
	if e != nil {
		return e
	}
	if nativeIdentity(i) != v.id || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && !s.expected[name].Reparse {
		return ErrTreePreserved
	}
	held, e := s.info(v.file)
	if e != nil || nativeIdentity(held) != v.id {
		return errors.Join(ErrTreePreserved, e)
	}
	return nil
}

// ObserveInventory enumerates names independently of source descriptors. Only
// exact expected leaves are opened; unknown directories are never traversed.
func (s *NativeObservationSession) ObserveInventory(ctx context.Context, limits TreeLimits) (out TreeInventory, runErr error) {
	if s == nil {
		return out, ErrTreePreserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root.mu.Lock()
	defer s.root.mu.Unlock()
	startRead, startResult := s.read, s.accounted
	var returnedBytes uint64
	defer func() {
		out.ReadBytes = s.read - startRead
		out.AccountedBytes = returnedBytes
		s.scratch -= returnedBytes
		if runErr != nil {
			s.latch(runErr)
			out.Complete = false
		}
	}()
	if e := s.live(ctx); e != nil {
		return out, e
	}
	maxEntries := s.limits.MaxEntries
	maxRead := s.limits.MaxReadBytes - s.read
	maxResult := s.limits.MaxResultBytes - s.accounted
	if limits.MaxEntries < 0 || limits.MaxDepth < 0 {
		return out, ErrTreeLimit
	}
	if limits.MaxEntries > 0 {
		maxEntries = min(maxEntries, limits.MaxEntries)
	}
	if limits.MaxReadBytes > 0 {
		maxRead = min(maxRead, limits.MaxReadBytes)
	}
	if limits.MaxResultBytes > 0 {
		maxResult = min(maxResult, limits.MaxResultBytes)
	}
	out.Tree = s.id
	out.Complete = !s.incomplete
	seen := make(map[string]bool)
	add := func(name, status string, id, retained FileIdentity, attrs uint32, cause error) error {
		cost := uint64(512 + len(name)*8)
		if cause != nil {
			cost += 8192
		}
		if len(out.Entries) >= maxEntries || cost > maxResult-min(returnedBytes+s.accounted-startResult, maxResult) {
			return ErrTreeLimit
		}
		if e := s.reserve(0, 0, cost); e != nil {
			return e
		}
		returnedBytes += cost
		v := InventoryEntry{Path: name, Status: status, Identity: id, RetainedIdentity: retained, Attributes: attrs}
		if cause != nil {
			f := fieldError(cause)
			v.NativeCode = f.NativeCode
			v.Failure = f.Detail
			if len(v.Failure) > 2048 {
				v.Failure = v.Failure[:2048]
			}
			s.latch(cause)
			s.recordFailure(name, retained, cause)
		}
		out.Entries = append(out.Entries, v)
		if status != "known" {
			out.Complete = false
			s.incomplete = true
		}
		return nil
	}
	if e := add(".", "known", s.id.Root, s.id.Root, windows.FILE_ATTRIBUTE_DIRECTORY, nil); e != nil {
		return out, e
	}
	seen["."] = true
	var walk func(string, int) error
	walk = func(prefix string, depth int) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if depth > s.limits.MaxDepth || limits.MaxDepth > 0 && depth > limits.MaxDepth {
			return ErrTreeLimit
		}
		if e := s.checkEntry(prefix); e != nil {
			if row := s.entries[prefix]; row != nil {
				s.recordFailure(prefix, row.id, e)
			}
			return e
		}
		dir := s.entries[prefix]
		if e := s.reserve(128, 0, 0); e != nil {
			return e
		}
		s.queryCapacity += 128
		before, e := s.info(dir.file)
		if e != nil {
			return e
		}
		class := uint32(windows.FileIdBothDirectoryRestartInfo)
		for {
			if e := ctx.Err(); e != nil {
				return e
			}
			const size = 64 << 10
			if size > maxRead-min(s.read-startRead, maxRead) || size > maxResult-min(s.scratch+s.accounted-startResult, maxResult) {
				return ErrTreeLimit
			}
			if e := s.reserve(size, 0, size); e != nil {
				return e
			}
			s.queryCapacity += size
			buffer := alignedNativeBuffer(size)
			e := s.queryDirectory(windows.Handle(dir.file.Fd()), class, buffer)
			if errors.Is(e, windows.ERROR_NO_MORE_FILES) {
				s.scratch -= size
				break
			}
			if e != nil {
				s.scratch -= size
				return e
			}
			for off := 0; ; {
				if off > len(buffer)-104 {
					s.scratch -= size
					return ErrTreePreserved
				}
				v := buffer[off:]
				next, n := binary.LittleEndian.Uint32(v), binary.LittleEndian.Uint32(v[60:])
				if n == 0 || n%2 != 0 || n > 510 || uint64(n) > uint64(len(v)-104) || next != 0 && (next%8 != 0 || next < 104+n || uint64(next) > uint64(len(v)-104)) {
					s.scratch -= size
					return ErrTreePreserved
				}
				u := make([]uint16, n/2)
				for j := range u {
					u[j] = binary.LittleEndian.Uint16(v[104+j*2:])
				}
				leaf := string(utf16.Decode(u))
				if !slices.Equal(u, utf16.Encode([]rune(leaf))) {
					s.scratch -= size
					return ErrTreePreserved
				}
				if leaf != "." && leaf != ".." {
					if _, e := treeName(leaf, 1); e != nil {
						s.scratch -= size
						return e
					}
					name := leaf
					if prefix != "." {
						if len(prefix)+len(leaf)+1 > 4096 {
							s.scratch -= size
							return ErrTreeLimit
						}
						name = prefix + "/" + leaf
					}
					attrs := binary.LittleEndian.Uint32(v[56:])
					nativeID := FileIdentity{VolumeSerial: s.id.Root.VolumeSerial, FileIndex: binary.LittleEndian.Uint64(v[96:])}
					p, known := s.expected[name]
					held := s.entries[name]
					retained := FileIdentity{}
					if held != nil {
						retained = held.id
					}
					status := "known"
					var cause error
					if seen[name] {
						status = "duplicate"
					} else if !known {
						status = "unknown"
					} else if (attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != p.Directory || (attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0) != p.Reparse {
						status = "changed-type"
					} else if held != nil && held.id != nativeID {
						status = "changed"
					}
					seen[name] = true
					short, shortErr := directoryShortName(v)
					if status == "known" && shortErr != nil {
						status = "failed-short-name"
						cause = shortErr
					}
					if status == "known" {
						if e := s.reserve(128, 0, 0); e != nil {
							s.scratch -= size
							return e
						}
						s.queryCapacity += 128
					}
					if status == "known" && held == nil {
						if e := s.retainHandle(); e != nil {
							s.scratch -= size
							return e
						}
						f, e := nativeTreeOpenShared(windows.Handle(dir.file.Fd()), leaf, windows.FILE_GENERIC_READ|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_OPEN_FOR_BACKUP_INTENT, windows.FILE_SHARE_READ, nil)
						if e != nil {
							s.handles--
							status = "denied"
							cause = e
						} else {
							// Retain acquired handles before fallible identity inspection.
							held = &nativeObservedEntry{file: f, parent: prefix, leaf: leaf, name: name, streams: map[string]*os.File{}}
							s.entries[name] = held
							s.order = append(s.order, held)
							i, e := s.info(f)
							if e != nil {
								status = "failed"
								cause = e
							} else {
								held.id = nativeIdentity(i)
								retained = held.id
								if held.id != nativeID || i.FileAttributes != attrs {
									status = "changed"
								}
							}
						}
					}
					if status == "known" {
						i, e := s.info(held.file)
						if e != nil {
							status = "failed"
							cause = e
						} else if nativeIdentity(i) != held.id {
							status = "changed"
						}
						if held.shortObserved && !slices.Equal(held.short, short) {
							status = "changed-short-name"
						}
						if !held.shortObserved {
							held.short = slices.Clone(short)
							held.shortObserved = true
						}
					}
					if e := add(name, status, nativeID, retained, attrs, cause); e != nil {
						s.scratch -= size
						return e
					}
					if status == "known" && p.Directory && !p.Reparse {
						if e := walk(name, depth+1); e != nil {
							s.scratch -= size
							return e
						}
					}
				}
				if next == 0 {
					break
				}
				off += int(next)
			}
			s.scratch -= size
			class = windows.FileIdBothDirectoryInfo
		}
		after, e := s.info(dir.file)
		if e != nil || after != before {
			return errors.Join(ErrTreePreserved, e)
		}
		return nil
	}
	if e := walk(".", 0); e != nil {
		return out, e
	}
	for name := range s.expected {
		if !seen[name] {
			retained := FileIdentity{}
			if v := s.entries[name]; v != nil {
				retained = v.id
			}
			if e := add(name, "missing", FileIdentity{}, retained, 0, nil); e != nil {
				return out, e
			}
		}
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path < out.Entries[j].Path })
	out.ReadBytes = s.read - startRead
	out.AccountedBytes = returnedBytes
	return out, s.live(ctx)
}

func (s *NativeObservationSession) Observe(ctx context.Context, name string, limits MetadataLimits) (out MetadataObservation, runErr error) {
	if s == nil {
		return out, ErrTreePreserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root.mu.Lock()
	defer s.root.mu.Unlock()
	defer func() { s.latch(runErr) }()
	if e := s.live(ctx); e != nil {
		return out, e
	}
	p, ok := s.expected[name]
	v := s.entries[name]
	if !ok || v == nil {
		return out, ErrTreePreserved
	}
	out.Identity = v.id
	defer func() {
		if runErr != nil {
			if out.Identity.FileIndex == 0 {
				out.Identity = v.id
			}
			s.recordFailure(name, v.id, runErr)
		}
	}()
	if e := s.checkEntry(name); e != nil {
		return out, e
	}
	l, e := metadataBounds(limits)
	if e != nil {
		return out, e
	}
	if l.MaxBufferBytes > 64<<10 {
		return out, ErrTreeLimit
	}
	scratch := nativeMetadataScratch(l)
	read := uint64(4*l.MaxBufferBytes + 64 + 128)
	if p.Reparse {
		read += 16384
	}
	// The returned metadata belongs to the caller's per-call result budget.
	// This session retains no raw metadata. Its peak scratch is reserved until
	// return; the private comparison caller accounts its own retained witnesses.
	if e = s.reserve(read, 0, scratch); e != nil {
		return out, e
	}
	s.queryCapacity += read
	defer func() { s.scratch -= scratch }()
	if e = s.retainHandle(); e != nil {
		return out, e
	}
	parent := s.root.parents[len(s.root.parents)-1]
	leaf := v.leaf
	if name != "." {
		parent = s.entries[v.parent].file
	}
	out, e = observeHeldMetadata(ctx, v.file, v.id, parent, leaf, l, p.Reparse)
	s.handles-- // the helper has returned and closed its temporary SACL open
	if e != nil {
		return out, e
	}
	if name == "." {
		out.ShortName = MetadataField{Status: "complete", Detail: "root has no source directory-entry short name"}
	} else {
		out.ShortName = MetadataField{Status: "complete"}
		out.ShortNameUTF16 = slices.Clone(v.short)
	}
	if len(out.NamedStreams) > s.limits.MaxStreams-s.streamRecords {
		return out, ErrTreeLimit
	}
	s.streamRecords += len(out.NamedStreams)
	if !out.Complete {
		s.incomplete = true
	}
	if !p.Reparse && out.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return out, ErrTreePreserved
	}
	return out, errors.Join(s.checkEntry(name), s.live(ctx))
}

// BeginMetadataPass resets only the stream-record counter. Cumulative read,
// handle and result bounds are never reset. This is not a snapshot boundary.
func (s *NativeObservationSession) BeginMetadataPass(ctx context.Context) error {
	if s == nil {
		return ErrTreePreserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root.mu.Lock()
	defer s.root.mu.Unlock()
	if e := s.live(ctx); e != nil {
		return e
	}
	s.streamRecords = 0
	return nil
}

func (s *NativeObservationSession) ReadOwnedAt(ctx context.Context, name, stream string, b []byte, off int64) (n int, runErr error) {
	if s == nil {
		return 0, ErrTreePreserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root.mu.Lock()
	defer s.root.mu.Unlock()
	defer func() { s.latch(runErr) }()
	if e := s.live(ctx); e != nil {
		return 0, e
	}
	if len(b) > 64<<10 || len(name) > 4096 || len(stream) > 1024 {
		return 0, ErrTreeLimit
	}
	if off < 0 {
		return 0, ErrTreePreserved
	}
	p, ok := s.expected[name]
	v := s.entries[name]
	if !ok || v == nil || p.Reparse || p.Directory && stream == "" {
		return 0, ErrTreePreserved
	}
	defer func() {
		if runErr != nil {
			s.recordFailure(name, v.id, runErr)
		}
	}()
	size := p.DefaultSize
	authorized := stream == ""
	for _, w := range p.Streams {
		if w.Name == stream {
			authorized = true
			size = w.Size
		}
	}
	if !authorized || uint64(off) > size {
		return 0, ErrTreePreserved
	}
	b = b[:min(uint64(len(b)), size-uint64(off))]
	if e := s.checkEntry(name); e != nil {
		return 0, e
	}
	if e := s.reserve(uint64(len(b)), 0, 0); e != nil {
		return 0, e
	}
	s.contentRead += uint64(len(b))
	f := v.file
	if stream != "" {
		f = v.streams[stream]
		if f == nil {
			if e := s.reserve(0, uint64(512+len(stream)*4), 0); e != nil {
				return 0, e
			}
			if e := s.retainHandle(); e != nil {
				return 0, e
			}
			var e error
			parent := s.entries[v.parent].file
			if name == "." {
				parent = s.root.parents[len(s.root.parents)-1]
			}
			f, e = nativeTreeOpenShared(windows.Handle(parent.Fd()), v.leaf+":"+stream+":$DATA", windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT, windows.FILE_SHARE_READ, nil)
			if e != nil {
				s.handles--
				return 0, e
			}
			v.streams[stream] = f
			v.streamOrder = append(v.streamOrder, stream)
		}
	}
	if e := s.reserve(128, 0, 0); e != nil {
		return 0, e
	}
	s.queryCapacity += 128
	before, e := s.info(f)
	if e != nil || nativeIdentity(before) != v.id || before.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return 0, errors.Join(ErrTreePreserved, e)
	}
	n, runErr = f.ReadAt(b, off)
	after, e := s.info(f)
	if e != nil || after != before {
		return n, errors.Join(runErr, ErrTreePreserved, e)
	}
	return n, errors.Join(runErr, s.checkEntry(name), s.live(ctx))
}

func (s *NativeObservationSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	s.closeErr = fmt.Errorf("%w: read-only observation scope %s [volume=%d file=%d]; durable claim unresolved", ErrTreePreserved, s.id.RelativePath, s.id.Root.VolumeSerial, s.id.Root.FileIndex)
	s.closeErr = errors.Join(s.closeErr, s.errorState)
	for j := len(s.order) - 1; j >= 0; j-- {
		v := s.order[j]
		name := v.name
		for k := len(v.streamOrder) - 1; k >= 0; k-- {
			stream := v.streamOrder[k]
			f := v.streams[stream]
			if e := s.closeFile(f); e != nil {
				if s.recordFailure(name+":"+stream, v.id, e) {
					s.closeErr = errors.Join(s.closeErr, fmt.Errorf("%s:%s [volume=%d file=%d]: %w", name, stream, v.id.VolumeSerial, v.id.FileIndex, e))
				}
			}
			s.handles--
		}
		if name != "." {
			if e := s.closeFile(v.file); e != nil {
				if s.recordFailure(name, v.id, e) {
					s.closeErr = errors.Join(s.closeErr, fmt.Errorf("%s [volume=%d file=%d]: %w", name, v.id.VolumeSerial, v.id.FileIndex, e))
				}
			}
			s.handles--
		}
	}
	// Close only root ADS opened by this session, never the borrowed root.
	if root := s.entries["."]; root != nil {
		for j := len(root.streamOrder) - 1; j >= 0; j-- {
			name := root.streamOrder[j]
			if e := s.closeFile(root.streams[name]); e != nil {
				if s.recordFailure(".:"+name, root.id, e) {
					s.closeErr = errors.Join(s.closeErr, e)
				}
			}
			s.handles--
		}
	}
	if s.failureEvidenceExhausted {
		s.closeErr = errors.Join(s.closeErr, ErrTreeLimit, fmt.Errorf("%s [volume=%d file=%d]: %w", s.terminalFailure.Path, s.terminalFailure.Identity.VolumeSerial, s.terminalFailure.Identity.FileIndex, s.terminalCause))
	}
	return s.closeErr
}
