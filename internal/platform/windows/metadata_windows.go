package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

type MetadataLimits struct {
	MaxBufferBytes, MaxStreams, MaxEAs int
	MaxReadBytes, MaxResultBytes       uint64
}
type MetadataField struct {
	Status     string
	NativeCode uint32
	Detail     string
	Raw        []byte
}
type StreamObservation struct {
	Name             []uint16
	Size, Allocation uint64
}
type EAObservation struct {
	Flags       byte
	Name, Value []byte
}
type MetadataObservation struct {
	Identity                                             FileIdentity
	VolumeSerial                                         uint64
	FileID128                                            [16]byte
	Attributes, LinkCount                                uint32
	CreationTime, AccessTime, WriteTime, ChangeTime      uint64
	Basic, FileID, Security, SACL, Streams, EAs, Reparse MetadataField
	NamedStreams                                         []StreamObservation
	ExtendedAttributes                                   []EAObservation
	ReparseTag                                           uint32
	ReadBytes                                            uint64
	Complete                                             bool
}

func (t *OwnedTree) observationParent(name string) (*os.File, string, error) {
	if name == "." {
		if len(t.parents) == 0 {
			return nil, "", ErrTreePreserved
		}
		return t.parents[len(t.parents)-1], filepath.Base(t.identity.RelativePath), nil
	}
	n, e := treeName(name, t.limits.MaxDepth)
	if e != nil {
		return nil, "", e
	}
	return t.parent(n)
}

func metadataBounds(l MetadataLimits) (MetadataLimits, error) {
	for n, p := range []*int{&l.MaxBufferBytes, &l.MaxStreams, &l.MaxEAs} {
		cap := []int{1 << 20, 256, 256}[n]
		if *p < 0 || *p > cap {
			return l, ErrTreeLimit
		}
		if *p == 0 {
			*p = []int{64 << 10, 256, 256}[n]
		}
	}
	if l.MaxReadBytes > 16<<20 || l.MaxResultBytes > 16<<20 {
		return l, ErrTreeLimit
	}
	if l.MaxReadBytes == 0 {
		l.MaxReadBytes = 4 << 20
	}
	if l.MaxResultBytes == 0 {
		l.MaxResultBytes = 4 << 20
	}
	// Includes raw buffers, decoded names/values, fixed records and scratch.
	if uint64(l.MaxBufferBytes)*12+uint64(l.MaxStreams+l.MaxEAs)*128+4096 > l.MaxResultBytes {
		return l, ErrTreeLimit
	}
	return l, nil
}
func fieldError(e error) MetadataField {
	if e == nil {
		return MetadataField{Status: "complete"}
	}
	f := MetadataField{Status: "failed", Detail: e.Error()}
	var errno windows.Errno
	if errors.As(e, &errno) {
		f.NativeCode = uint32(errno)
	}
	var nt windows.NTStatus
	if errors.As(e, &nt) {
		f.NativeCode = uint32(nt)
		e = errors.Join(e, nt.Errno())
	}
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		f.Status = "access-denied"
	}
	if errors.Is(e, windows.ERROR_PRIVILEGE_NOT_HELD) {
		f.Status = "missing-privilege"
	}
	if errors.Is(e, windows.ERROR_NOT_SUPPORTED) || errors.Is(e, windows.ERROR_INVALID_FUNCTION) || errors.Is(e, windows.ERROR_EAS_NOT_SUPPORTED) {
		f.Status = "unsupported"
	}
	return f
}
func safeStreamName(s string) (string, error) {
	if s == "::$DATA" {
		return "", nil
	}
	if !strings.HasPrefix(s, ":") || !strings.HasSuffix(s, ":$DATA") {
		return "", errors.New("unsupported stream type")
	}
	n := strings.TrimSuffix(strings.TrimPrefix(s, ":"), ":$DATA")
	if n == "" || strings.ContainsAny(n, "/\\:") {
		return "", errors.New("unsafe stream name")
	}
	if _, e := model.ValidateRelativePath(n); e != nil {
		return "", e
	}
	return n, nil
}
func parseStreams(b []byte, maxCount int) ([]StreamObservation, error) {
	var out []StreamObservation
	for off := 0; ; {
		if len(out) >= maxCount {
			return nil, ErrTreeLimit
		}
		if off > len(b)-24 {
			return nil, ErrTreePreserved
		}
		v := b[off:]
		next, n := binary.LittleEndian.Uint32(v), binary.LittleEndian.Uint32(v[4:])
		if n == 0 || n%2 != 0 || uint64(n) > uint64(len(v)-24) || n > 8192 {
			return nil, ErrTreePreserved
		}
		end := 24 + int(n)
		if next != 0 && (next%8 != 0 || next < uint32(end) || uint64(next) > uint64(len(v)-24)) {
			return nil, ErrTreePreserved
		}
		name := make([]uint16, int(n)/2)
		for j := range name {
			name[j] = binary.LittleEndian.Uint16(v[24+j*2:])
		}
		if _, e := safeStreamName(string(utf16.Decode(name))); e != nil {
			return nil, e
		}
		size, alloc := binary.LittleEndian.Uint64(v[8:]), binary.LittleEndian.Uint64(v[16:])
		if size > 1<<63-1 || alloc > 1<<63-1 {
			return nil, ErrTreePreserved
		}
		out = append(out, StreamObservation{Name: name, Size: size, Allocation: alloc})
		if next == 0 {
			return out, nil
		}
		off += int(next)
	}
}
func parseEAs(b []byte, maxCount int) ([]EAObservation, error) {
	var out []EAObservation
	for off := 0; ; {
		if len(out) >= maxCount {
			return nil, ErrTreeLimit
		}
		if off > len(b)-8 {
			return nil, ErrTreePreserved
		}
		v := b[off:]
		next := binary.LittleEndian.Uint32(v)
		n, m := int(v[5]), int(binary.LittleEndian.Uint16(v[6:]))
		end := 8 + n + 1 + m
		if n == 0 || n >= 255 || end > len(v) || v[8+n] != 0 || v[4]&^byte(0x80) != 0 || next != 0 && (next%4 != 0 || next < uint32(end) || uint64(next) > uint64(len(v)-8)) {
			return nil, ErrTreePreserved
		}
		for _, c := range v[8 : 8+n] {
			if c < 32 || c > 127 || strings.ContainsRune(`\/:*?"<>|,+=[];`, rune(c)) {
				return nil, ErrTreePreserved
			}
		}
		out = append(out, EAObservation{Flags: v[4], Name: slices.Clone(v[8 : 8+n]), Value: slices.Clone(v[9+n : end])})
		if next == 0 {
			if end != len(v) {
				return nil, ErrTreePreserved
			}
			return out, nil
		}
		off += int(next)
	}
}

// Security uses the documented file-handle API. GetSecurityInfo owns an OS
// LocalAlloc result; its native internal allocation is outside our Go result
// budget. Check the returned descriptor length before any Go copy; LocalFree
// errors are retained. No callback/opaque ACE data is interpreted or dropped.
func securityField(h windows.Handle, mask windows.SECURITY_INFORMATION, maxBytes int) MetadataField {
	var sd *windows.SECURITY_DESCRIPTOR
	r, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("GetSecurityInfo").Call(uintptr(h), uintptr(windows.SE_FILE_OBJECT), uintptr(mask), 0, 0, 0, 0, uintptr(unsafe.Pointer(&sd)))
	if r != 0 {
		return fieldError(windows.Errno(r))
	}
	if sd == nil {
		return fieldError(ErrTreePreserved)
	}
	n := sd.Length()
	f := MetadataField{Status: "complete"}
	if n < 20 || uint64(n) > uint64(maxBytes) {
		f = fieldError(ErrTreeLimit)
	} else {
		f.Raw = slices.Clone(unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(n)))
	}
	if _, e := windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(sd)))); e != nil {
		f = fieldError(e)
	}
	return f
}

// Observe reads only an exact held owned object or root. It never accepts an
// arbitrary path, opens an executable, follows a reparse target, or adjusts the
// effective token. Incomplete/denied fields remain explicit and Complete=false.
func (t *OwnedTree) Observe(ctx context.Context, name string, limits MetadataLimits) (out MetadataObservation, runErr error) {
	if t == nil || ctx == nil {
		return out, ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	l, e := metadataBounds(limits)
	if e != nil {
		return out, e
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if e = t.validate(); e != nil {
		return out, e
	}
	v, e := t.entry(name)
	if e != nil {
		return out, e
	}
	i, e := nativeInfo(v.file)
	if e != nil || nativeIdentity(i) != v.id {
		return out, errors.Join(ErrTreePreserved, e)
	}
	out.Identity = v.id
	out.Attributes = i.FileAttributes
	out.LinkCount = i.NumberOfLinks
	charge := func(n int) error {
		if uint64(n) > l.MaxReadBytes-out.ReadBytes {
			return ErrTreeLimit
		}
		out.ReadBytes += uint64(n)
		return ctx.Err()
	}
	h := windows.Handle(v.file.Fd())
	query := func(class uint32, n int) (MetadataField, error) {
		if e := charge(n); e != nil {
			return MetadataField{}, e
		}
		b := alignedNativeBuffer(n)
		e := windows.GetFileInformationByHandleEx(h, class, &b[0], uint32(n))
		f := fieldError(e)
		if e == nil {
			f.Raw = b
		}
		return f, nil
	}
	if out.Basic, e = query(windows.FileBasicInfo, 40); e != nil {
		return out, e
	}
	if out.Basic.Status == "complete" {
		b := out.Basic.Raw
		out.CreationTime = binary.LittleEndian.Uint64(b)
		out.AccessTime = binary.LittleEndian.Uint64(b[8:])
		out.WriteTime = binary.LittleEndian.Uint64(b[16:])
		out.ChangeTime = binary.LittleEndian.Uint64(b[24:])
		out.Attributes = binary.LittleEndian.Uint32(b[32:])
	}
	if out.FileID, e = query(windows.FileIdInfo, 24); e != nil {
		return out, e
	}
	if out.FileID.Status == "complete" {
		out.VolumeSerial = binary.LittleEndian.Uint64(out.FileID.Raw)
		copy(out.FileID128[:], out.FileID.Raw[8:])
	}
	if e = charge(l.MaxBufferBytes); e != nil {
		return out, e
	}
	out.Security = securityField(h, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION, l.MaxBufferBytes)
	if e = charge(l.MaxBufferBytes); e != nil {
		return out, e
	}
	parent, leaf, e := t.observationParent(name)
	var saclFile *os.File
	if e == nil {
		saclFile, e = nativeTreeOpen(windows.Handle(parent.Fd()), leaf, windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY, windows.FILE_OPEN, 0, nil)
	}
	if e != nil {
		out.SACL = fieldError(e)
	} else {
		actual, err := nativeInfo(saclFile)
		if err != nil || nativeIdentity(actual) != v.id {
			out.SACL = fieldError(errors.Join(ErrTreePreserved, err))
		} else {
			out.SACL = securityField(windows.Handle(saclFile.Fd()), windows.SACL_SECURITY_INFORMATION, l.MaxBufferBytes)
		}
		if e = saclFile.Close(); e != nil {
			out.SACL = fieldError(e)
		}
	}
	if out.Streams, e = query(windows.FileStreamInfo, l.MaxBufferBytes); e != nil {
		return out, e
	}
	if out.Streams.Status == "complete" {
		out.NamedStreams, e = parseStreams(out.Streams.Raw, l.MaxStreams)
		if e != nil {
			raw := out.Streams.Raw
			out.Streams = fieldError(e)
			out.Streams.Raw = raw
		}
	} else if out.Streams.NativeCode == uint32(windows.ERROR_HANDLE_EOF) {
		out.Streams = MetadataField{Status: "complete", NativeCode: uint32(windows.ERROR_HANDLE_EOF), Detail: "no data streams"}
	}
	if e = charge(l.MaxBufferBytes); e != nil {
		return out, e
	}
	buf := alignedNativeBuffer(l.MaxBufferBytes)
	ios := windows.IO_STATUS_BLOCK{}
	e = windows.NtQueryEaFile(h, &ios, &buf[0], uint32(len(buf)), false, nil, 0, nil, true)
	out.EAs = fieldError(e)
	if errors.Is(e, windows.STATUS_NO_EAS_ON_FILE) {
		out.EAs = MetadataField{Status: "complete", NativeCode: uint32(windows.STATUS_NO_EAS_ON_FILE), Detail: "no EAs on file"}
	} else if e == nil || errors.Is(e, windows.STATUS_BUFFER_OVERFLOW) {
		partial := e != nil
		if ios.Information > uintptr(len(buf)) {
			out.EAs = fieldError(ErrTreeLimit)
		} else {
			out.EAs.Raw = buf[:int(ios.Information)]
			if partial {
				out.EAs.Status = "incomplete"
			}
			out.ExtendedAttributes, e = parseEAs(out.EAs.Raw, l.MaxEAs)
			if e != nil {
				raw := out.EAs.Raw
				out.EAs = fieldError(e)
				out.EAs.Raw = raw
			}
		}
	}
	if out.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		out.Reparse = MetadataField{Status: "not-present"}
	} else {
		if e = charge(16384); e != nil {
			return out, e
		}
		b := make([]byte, 16384)
		var n uint32
		e = windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &b[0], uint32(len(b)), &n, nil)
		out.Reparse = fieldError(e)
		if e == nil {
			if n < 8 || n > uint32(len(b)) || int(binary.LittleEndian.Uint16(b[4:]))+8 != int(n) {
				out.Reparse = fieldError(ErrTreePreserved)
			} else {
				out.Reparse.Raw = b[:n]
				out.ReparseTag = binary.LittleEndian.Uint32(b)
			}
		}
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	end, e := nativeInfo(v.file)
	if e != nil || end != i {
		return out, errors.Join(ErrTreePreserved, e, fmt.Errorf("metadata changed during observation"))
	}
	out.Complete = out.Basic.Status == "complete" && out.FileID.Status == "complete" && out.Security.Status == "complete" && out.SACL.Status == "complete" && out.Streams.Status == "complete" && out.EAs.Status == "complete" && (out.Reparse.Status == "complete" || out.Reparse.Status == "not-present")
	return out, nil
}
