package engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

type ModuleIdentity struct {
	Name, SHA256 string
	Size         int64
	MappedBytes  uint32
}
type ImageInformation struct {
	Index                                            uint32
	Architecture, Edition, InstallationType, Version string
}
type NativeObservation struct {
	OutputSHA256, RecipeDigest, ProofDigest string
	Provider                                platform.DLLIdentity
	Host                                    model.Host
	ImageCount                              uint32
	FileXMLSHA256, ImageXMLSHA256           string
	Image                                   ImageInformation
	Modules                                 []ModuleIdentity
	LastOperation                           string
	FormatInteroperable                     bool
}

// InspectReadOnly is the one fixed documented inspection path. No arbitrary
// path/provider/flag/callback is accepted. Native allocation and one synchronous
// API call cannot be preempted; cancellation/60s are checked between calls.
func InspectReadOnly(ctx context.Context, a *Artifact) (out NativeObservation, runErr error) {
	if ctx == nil || a == nil {
		return out, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return out, os.ErrClosed
	}
	s := a.receipt
	if a.file == nil || a.store == nil || !s.BytesVerified || s.RecipeDigest == "" || s.ProofDigest == "" || s.Size > 8<<30 || s.Size < s.XMLOffset || s.Size-s.XMLOffset > 1<<20 {
		return out, ErrInput
	}
	if e := a.file.Verify(ctx, model.DigestSHA256, s.SHA256, s.SHA256); e != nil {
		return out, e
	}
	// Expectations were fixed from the original source recipe by Reconstruct,
	// independently of this produced WIM and the native parser's response.
	expected := a.expected
	if expected.Index != 1 || expected.Architecture == "" || expected.Edition == "" || expected.Version == "" {
		return out, ErrInput
	}
	out.OutputSHA256 = s.SHA256
	out.RecipeDigest = s.RecipeDigest
	out.ProofDigest = s.ProofDigest
	var e error
	out.Host, e = platform.DetectHost(ctx)
	if e != nil {
		return out, e
	}
	deadline := time.Now().Add(60 * time.Second)
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		return nil
	}
	dll, e := platform.OpenSystemDLL(ctx, "wimgapi.dll")
	if e != nil {
		return out, e
	}
	out.Provider = dll.Identity()
	var file, image uintptr
	var temp *nativeTemp
	var closeProc uintptr
	defer func() {
		// Capture operation-time mappings before handles/provider are unloaded,
		// including on first native failure. This is an observation, not Toolchain.
		if len(out.Modules) == 0 {
			var e error
			out.Modules, e = loadedModules(ctx)
			runErr = errors.Join(runErr, e)
		}
		for _, h := range []uintptr{image, file} {
			if h != 0 {
				ok, _, e := syscall.SyscallN(closeProc, h)
				if ok == 0 {
					runErr = errors.Join(runErr, nativeError("WIMCloseHandle", e))
				}
			}
		}
		if temp != nil {
			runErr = errors.Join(runErr, temp.Close())
		}
		runErr = errors.Join(runErr, dll.Close(), a.file.Verify(ctx, model.DigestSHA256, s.SHA256, s.SHA256))
		if runErr != nil {
			out.FormatInteroperable = false
		}
	}()
	procs := map[string]uintptr{}
	for _, name := range []string{"WIMCreateFile", "WIMGetImageCount", "WIMGetImageInformation", "WIMSetTemporaryPath", "WIMLoadImage", "WIMCloseHandle"} {
		p, e := dll.Proc(name)
		if e != nil {
			return out, e
		}
		procs[name] = p
	}
	closeProc = procs["WIMCloseHandle"]
	// Retained official Microsoft header SHA256 8aafd624...35cd7a:
	// WIM_GENERIC_READ=GENERIC_READ, WIM_OPEN_EXISTING=OPEN_EXISTING,
	// WIM_COMPRESS_NONE=0. No VERIFY/SHARE_WRITE/NO_APPLY/undocumented flags.
	path, e := windows.UTF16PtrFromString(filepath.Join(a.store.Path(), a.name))
	if e != nil {
		return out, e
	}
	var created uint32
	if e = check(); e != nil {
		return out, e
	}
	out.LastOperation = "WIMCreateFile"
	file, _, errno := syscall.SyscallN(procs[out.LastOperation], uintptr(unsafe.Pointer(path)), windows.GENERIC_READ, windows.OPEN_EXISTING, 0, 0, uintptr(unsafe.Pointer(&created)))
	runtime.KeepAlive(path)
	if file == 0 {
		return out, nativeError(out.LastOperation, errno)
	}
	if created != 1 {
		return out, ErrIntegrity
	}
	if e = check(); e != nil {
		return out, e
	}
	out.LastOperation = "WIMGetImageCount"
	count, _, errno := syscall.SyscallN(procs[out.LastOperation], file)
	out.ImageCount = uint32(count)
	if count != 1 {
		return out, nativeError(out.LastOperation, errno)
	}
	information := func(h uintptr) (result []byte, runErr error) {
		if e := check(); e != nil {
			return nil, e
		}
		out.LastOperation = "WIMGetImageInformation"
		var ptr unsafe.Pointer
		var size uint32
		ok, _, e := syscall.SyscallN(procs[out.LastOperation], h, uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&size)))
		if ok == 0 {
			return nil, nativeError(out.LastOperation, e)
		}
		if ptr == nil {
			return nil, ErrIntegrity
		}
		defer func() { _, e := windows.LocalFree(windows.Handle(uintptr(ptr))); runErr = errors.Join(runErr, e) }()
		if size == 0 || size > 1<<20 || size%2 != 0 {
			return nil, ErrLimit
		}
		return append([]byte(nil), unsafe.Slice((*byte)(ptr), int(size))...), nil
	}
	fileXML, e := information(file)
	if e != nil {
		return out, e
	}
	out.FileXMLSHA256 = sum256(fileXML)
	observed, e := imageInformation(fileXML)
	if e != nil || observed != expected {
		return out, errors.Join(ErrIntegrity, e)
	}
	// Microsoft WIMLoadImage explicitly requires WIMSetTemporaryPath for its
	// metadata cache. A generated protected empty scope contains only this call's
	// cache. Leftover/unknown entries are preserved, never recursively removed.
	temp, e = newNativeTemp()
	if e != nil {
		return out, e
	}
	tempPath, e := windows.UTF16PtrFromString(temp.workspace.Path())
	if e != nil {
		return out, e
	}
	if e = check(); e != nil {
		return out, e
	}
	out.LastOperation = "WIMSetTemporaryPath"
	ok, _, errno := syscall.SyscallN(procs[out.LastOperation], file, uintptr(unsafe.Pointer(tempPath)))
	runtime.KeepAlive(tempPath)
	if ok == 0 {
		return out, nativeError(out.LastOperation, errno)
	}
	if e = check(); e != nil {
		return out, e
	}
	out.LastOperation = "WIMLoadImage"
	temp.cacheAllowed = true
	image, _, errno = syscall.SyscallN(procs[out.LastOperation], file, 1)
	if image == 0 {
		return out, nativeError(out.LastOperation, errno)
	}
	if e = temp.Check(); e != nil {
		return out, e
	}
	imageXML, e := information(image)
	if e != nil {
		return out, e
	}
	out.ImageXMLSHA256 = sum256(imageXML)
	out.Image, e = imageInformation(imageXML)
	if e != nil || out.Image != expected {
		return out, errors.Join(ErrIntegrity, e)
	}
	out.Modules, e = loadedModules(ctx)
	if e != nil {
		return out, e
	}
	if e = check(); e != nil {
		return out, e
	}
	out.FormatInteroperable = true
	return out, nil
}
func nativeError(op string, e syscall.Errno) error {
	if e == 0 {
		return fmt.Errorf("%s failed without Win32 error", op)
	}
	return fmt.Errorf("%s: Win32 %d: %w", op, uint32(e), e)
}
func sum256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func imageInformation(b []byte) (ImageInformation, error) {
	var out ImageInformation
	if len(b)%2 != 0 {
		return out, ErrIntegrity
	}
	u := make([]uint16, len(b)/2)
	for n := range u {
		u[n] = binary.LittleEndian.Uint16(b[n*2:])
	}
	text := strings.Trim(string(utf16.Decode(u)), "\ufeff\x00 \r\n\t")
	type image struct {
		Index   uint32 `xml:"INDEX,attr"`
		Windows struct {
			Arch    string `xml:"ARCH"`
			Edition string `xml:"EDITIONID"`
			Type    string `xml:"INSTALLATIONTYPE"`
			Version struct {
				Major   string `xml:"MAJOR"`
				Minor   string `xml:"MINOR"`
				Build   string `xml:"BUILD"`
				SPBuild string `xml:"SPBUILD"`
			} `xml:"VERSION"`
		} `xml:"WINDOWS"`
	}
	var doc struct {
		XMLName xml.Name
		image
		Images []image `xml:"IMAGE"`
	}
	if e := xml.Unmarshal([]byte(text), &doc); e != nil {
		return out, ErrIntegrity
	}
	im := doc.image
	if doc.XMLName.Local == "WIM" {
		if len(doc.Images) != 1 {
			return out, ErrIntegrity
		}
		im = doc.Images[0]
	} else if doc.XMLName.Local != "IMAGE" {
		return out, ErrIntegrity
	}
	w := im.Windows
	out = ImageInformation{im.Index, w.Arch, w.Edition, w.Type, strings.Join([]string{w.Version.Major, w.Version.Minor, w.Version.Build, w.Version.SPBuild}, ".")}
	if out.Index != 1 || out.Edition == "" || out.Architecture == "" {
		return out, ErrIntegrity
	}
	return out, nil
}

func loadedModules(ctx context.Context) (out []ModuleIdentity, runErr error) {
	snap, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(os.Getpid()))
	if e != nil {
		return nil, e
	}
	defer func() { runErr = errors.Join(runErr, windows.CloseHandle(snap)) }()
	m := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	var total uint64
	for e = windows.Module32First(snap, &m); e == nil; e = windows.Module32Next(snap, &m) {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if len(out) >= 256 {
			return out, ErrLimit
		}
		path := windows.UTF16ToString(m.ExePath[:])
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return out, err
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return out, err
		}
		f := os.NewFile(uintptr(h), path)
		info, err := f.Stat()
		var native windows.ByHandleFileInformation
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 128<<20 || windows.GetFileInformationByHandle(h, &native) != nil || native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			f.Close()
			return out, ErrIntegrity
		}
		if uint64(info.Size()) > 512<<20-total {
			f.Close()
			return out, ErrLimit
		}
		total += uint64(info.Size())
		hash := sha256.New()
		_, err = io.CopyBuffer(hash, f, make([]byte, 64<<10))
		ce := f.Close()
		if err != nil || ce != nil {
			return out, errors.Join(err, ce)
		}
		out = append(out, ModuleIdentity{filepath.Base(path), hex.EncodeToString(hash.Sum(nil)), info.Size(), m.ModBaseSize})
	}
	if e != windows.ERROR_NO_MORE_FILES {
		return out, e
	}
	return out, nil
}

type nativeTemp struct {
	workspace    *platform.Workspace
	root, parent *os.Root
	initial      os.FileInfo
	ownerInfo    os.FileInfo
	ownerSHA256  string
	closed       bool
	cacheAllowed bool
	closeErr     error
}

func newNativeTemp() (*nativeTemp, error) {
	return newNativeTempWith(nativeTempConstructorOps{os.OpenRoot, (*os.Root).Close, (*platform.Workspace).Close})
}

// Private constructor-only filesystem seam; it cannot select a native provider
// or change the fixed inspection operation.
type nativeTempConstructorOps struct {
	openRoot       func(string) (*os.Root, error)
	closeRoot      func(*os.Root) error
	closeWorkspace func(*platform.Workspace) error
}

func newNativeTempWith(ops nativeTempConstructorOps) (result *nativeTemp, runErr error) {
	v, e := platform.InspectStorage(os.TempDir())
	if e != nil {
		return nil, e
	}
	if v.AvailableBytes < 256<<20 {
		return nil, ErrLimit
	}
	w, e := platform.CreateWorkspace(os.TempDir(), "wim-read-only-cache")
	if e != nil {
		return nil, e
	}
	// Until both extra roots are transferred to nativeTemp, this guard owns
	// every acquired handle. An incomplete custody chain cannot authorize
	// directory removal: preserve the fresh scope and report its exact identity.
	var r, p *os.Root
	constructorOwned := true
	defer func() {
		if !constructorOwned {
			return
		}
		var closeErr error
		if p != nil {
			closeErr = errors.Join(closeErr, ops.closeRoot(p))
		}
		if r != nil {
			closeErr = errors.Join(closeErr, ops.closeRoot(r))
		}
		closeErr = errors.Join(closeErr, ops.closeWorkspace(w))
		result = nil
		runErr = fmt.Errorf("native cache preserved at %s (scope=%s): %w", w.Path(), filepath.Base(w.Path()), errors.Join(runErr, closeErr))
	}()
	r, e = ops.openRoot(w.Path())
	if e != nil {
		return nil, e
	}
	p, e = ops.openRoot(filepath.Dir(w.Path()))
	if e != nil {
		return nil, e
	}
	info, e := r.Stat(".")
	t := &nativeTemp{workspace: w, root: r, parent: p, initial: info}
	constructorOwned = false
	if e != nil {
		return nil, errors.Join(e, t.Close())
	}
	owner, e := r.Open(".uupbuilder-owner.json")
	if e != nil {
		return nil, errors.Join(e, t.Close())
	}
	t.ownerInfo, e = owner.Stat()
	body, re := io.ReadAll(io.LimitReader(owner, 4097))
	e = errors.Join(e, re, owner.Close())
	if e != nil || len(body) > 4096 {
		return nil, errors.Join(ErrIntegrity, e, t.Close())
	}
	t.ownerSHA256 = sum256(body)
	if e = t.Check(); e != nil {
		return nil, errors.Join(e, t.Close())
	}
	return t, nil
}
func (t *nativeTemp) Check() error {
	if t.closed {
		return os.ErrClosed
	}
	now, e := t.root.Stat(".")
	named, se := t.parent.Stat(filepath.Base(t.workspace.Path()))
	if e != nil || se != nil || t.initial == nil || !os.SameFile(now, t.initial) || !os.SameFile(named, t.initial) {
		return ErrIntegrity
	}
	f, e := t.root.Open(".")
	if e != nil {
		return e
	}
	entries, e := f.ReadDir(34)
	e = errors.Join(e, f.Close())
	if e != nil && e != io.EOF {
		return e
	}
	if len(entries) > 33 {
		return ErrLimit
	}
	var total uint64
	foundOwner := false
	for _, en := range entries {
		if en.Name() != ".uupbuilder-owner.json" && !t.cacheAllowed {
			return ErrIntegrity
		}
		info, e := en.Info()
		if e != nil || info.IsDir() || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > 64<<20 {
			return ErrIntegrity
		}
		file, e := t.root.Open(en.Name())
		if e != nil {
			return e
		}
		current, e := file.Stat()
		var native windows.ByHandleFileInformation
		if e != nil || !os.SameFile(info, current) || windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &native) != nil || native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || native.NumberOfLinks != 1 {
			file.Close()
			return ErrIntegrity
		}
		if en.Name() == ".uupbuilder-owner.json" {
			foundOwner = true
			body, re := io.ReadAll(io.LimitReader(file, 4097))
			if re != nil || len(body) > 4096 || t.ownerInfo == nil || !os.SameFile(t.ownerInfo, current) || sum256(body) != t.ownerSHA256 {
				file.Close()
				return ErrIntegrity
			}
		}
		if e = file.Close(); e != nil {
			return e
		}
		total += uint64(info.Size())
		if total > 128<<20 {
			return ErrLimit
		}
	}
	if !foundOwner {
		return ErrIntegrity
	}
	return nil
}
func (t *nativeTemp) Close() error {
	if t.closed {
		return t.closeErr
	}
	checkErr := t.Check()
	t.closed = true
	finish := func(e error) error { t.closeErr = e; return e }
	f, e := t.root.Open(".")
	if e != nil {
		return finish(errors.Join(e, t.root.Close(), t.workspace.Close(), t.parent.Close()))
	}
	entries, re := f.ReadDir(2)
	re = errors.Join(re, f.Close())
	if re == io.EOF {
		re = nil
	}
	// WIMGAPI must release/remove its cache when its handles close. This owner
	// never adopts or deletes an unexplained native/foreign leftover.
	if checkErr != nil || re != nil || len(entries) != 1 || entries[0].Name() != ".uupbuilder-owner.json" {
		return finish(fmt.Errorf("native cache preserved at %s: %w", t.workspace.Path(), errors.Join(ErrIntegrity, checkErr, re, t.root.Close(), t.workspace.Close(), t.parent.Close())))
	}
	e = t.root.Remove(".uupbuilder-owner.json")
	e = errors.Join(e, t.root.Close(), t.workspace.Close())
	if e == nil {
		named, se := t.parent.Stat(filepath.Base(t.workspace.Path()))
		if se != nil || !os.SameFile(t.initial, named) {
			e = ErrIntegrity
		} else {
			e = t.parent.Remove(filepath.Base(t.workspace.Path()))
		}
	}
	return finish(errors.Join(e, t.parent.Close()))
}
