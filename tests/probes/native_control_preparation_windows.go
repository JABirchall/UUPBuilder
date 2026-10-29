package probes

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

// All providers are installed native Windows components. No source executable
// is explicitly launched. DISM may internally select image servicing code;
// that normal trust boundary is part of the separately reviewed action.
func controlReadLock(path string, directory bool) (*os.File, error) {
	return controlDataLock(path, directory, false)
}

// Installed components legitimately have WinSxS hardlinks. This is READ-ONLY
// custody: no alias can obtain write/delete sharing while the handle is held.
// Native dispatch separately pins canonical System32 path, file ID/hash/version.
func controlComponentReadLock(path string) (*os.File, error) {
	return controlDataLock(path, false, true)
}
func controlDataLock(path string, directory, sharedComponent bool) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil {
		f.Close()
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!directory && !sharedComponent && info.NumberOfLinks != 1) {
		f.Close()
		return nil, fmt.Errorf("control refuses file %s: reparse=%v links=%d", path, info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, info.NumberOfLinks)
	}
	return f, nil
}
func controlPinFile(f *os.File, binary bool, source bool) (p controlPin, err error) {
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return p, errors.New("control requires a regular file")
	}
	p.Size = st.Size()
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return p, err
	}
	p.Identity = platform.FileIdentity{VolumeSerial: info.VolumeSerialNumber, FileIndex: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)}
	p.Links = info.NumberOfLinks
	if _, err = f.Seek(0, 0); err != nil {
		return p, err
	}
	sha := sha256.New()
	one := sha1.New()
	var dst io.Writer = sha
	if source {
		dst = io.MultiWriter(sha, one)
	}
	if _, err = io.Copy(dst, f); err != nil {
		return p, err
	}
	p.SHA256 = hex.EncodeToString(sha.Sum(nil))
	if source {
		p.SHA1 = hex.EncodeToString(one.Sum(nil))
	}
	if binary {
		image, e := pe.NewFile(f)
		if e != nil {
			return p, e
		}
		p.Machine = image.Machine
		image.Close()
	}
	return p, nil
}
func controlVersions(path string) (out controlVersionFields, err error) {
	n, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || n == 0 || n > 16<<20 {
		return out, errors.New("tool version unavailable or oversized")
	}
	b := make([]byte, n)
	if err = windows.GetFileVersionInfo(path, 0, n, unsafe.Pointer(&b[0])); err != nil {
		return out, err
	}
	var v *[13]uint32
	var size uint32
	if err = windows.VerQueryValue(unsafe.Pointer(&b[0]), `\`, unsafe.Pointer(&v), &size); err != nil || v == nil || size < 52 || v[0] != 0xfeef04bd {
		return out, errors.New("invalid fixed tool version")
	}
	format := func(a, b uint32) string { return fmt.Sprintf("%d.%d.%d.%d", a>>16, a&65535, b>>16, b&65535) }
	out.NumericFileVersion = format(v[2], v[3])
	out.NumericProductVersion = format(v[4], v[5])
	var translations *uint16
	var length uint32
	if err = windows.VerQueryValue(unsafe.Pointer(&b[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&translations), &length); err != nil || translations == nil || length < 4 || length%4 != 0 || length > 128 {
		return out, errors.New("unsupported version translation table")
	}
	units := unsafe.Slice(translations, int(length/2))
	language, codepage := units[0], units[1]
	for i := 0; i < len(units); i += 2 {
		if units[i] == 0x409 {
			language, codepage = units[i], units[i+1]
			break
		}
	}
	query := func(name string) (string, error) {
		var ptr *uint16
		var size uint32
		key := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, language, codepage, name)
		if err := windows.VerQueryValue(unsafe.Pointer(&b[0]), key, unsafe.Pointer(&ptr), &size); err != nil || ptr == nil || size == 0 || size > 4096 {
			return "", errors.New("display version unavailable")
		}
		start := uintptr(unsafe.Pointer(&b[0]))
		address := uintptr(unsafe.Pointer(ptr))
		if address < start || address+uintptr(size)*2 > start+uintptr(len(b)) {
			return "", errors.New("display version outside returned buffer")
		}
		return windows.UTF16ToString(unsafe.Slice(ptr, int(size))), nil
	}
	out.DisplayFileVersion, err = query("FileVersion")
	if err != nil {
		return out, err
	}
	out.DisplayProductVersion, err = query("ProductVersion")
	return out, err
}

type controlTokenObservation struct {
	SID                    string
	ElevationType          uint32
	LinkedAvailable        bool
	LinkedSID, LinkedError string
}

func observeControlToken() (o controlTokenObservation, err error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return o, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return o, err
	}
	o.SID = user.User.Sid.String()
	var size uint32
	if err = windows.GetTokenInformation(token, windows.TokenElevationType, (*byte)(unsafe.Pointer(&o.ElevationType)), 4, &size); err != nil {
		return o, err
	}
	linked, e := token.GetLinkedToken()
	if e != nil {
		o.LinkedError = e.Error()
		return o, nil
	}
	defer linked.Close()
	u, e := linked.GetTokenUser()
	if e != nil {
		o.LinkedError = e.Error()
		return o, nil
	}
	o.LinkedAvailable = true
	o.LinkedSID = u.User.Sid.String()
	return o, nil
}
func controlFree(path string) (uint64, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	var free, total, available uint64
	e = windows.GetDiskFreeSpaceEx(p, &available, &total, &free)
	return available, e
}
func controlDirectoryID(f *os.File) (platform.FileIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return platform.FileIdentity{}, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return platform.FileIdentity{}, errors.New("unsafe control directory")
	}
	return platform.FileIdentity{VolumeSerial: info.VolumeSerialNumber, FileIndex: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)}, nil
}
func verifyControlDirectory(path string, want platform.FileIdentity) error {
	f, err := controlReadLock(path, true)
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := controlDirectoryID(f)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("sealed role directory identity changed")
	}
	return nil
}
func controlSync(w *platform.Workspace, name string, b []byte, exclusive bool) error {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if exclusive {
		flags = os.O_CREATE | os.O_WRONLY | os.O_EXCL
	}
	f, err := w.OpenFile(name, flags, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
func controlJSON(w *platform.Workspace, name string, v any, exclusive bool) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return controlSync(w, name, b, exclusive)
}
func controlCopy(dst *os.File, src *os.File) error {
	if _, err := src.Seek(0, 0); err != nil {
		return err
	}
	_, err := io.Copy(dst, src)
	if err == nil {
		err = dst.Sync()
	}
	return err
}

// prepareControl creates protected namespaces and performs only inert file,
// PE/version, token, host and filesystem reads. It never calls Store.Begin,
// starts a child, initializes DISM, or invokes an image API.
func prepareControl(ctx context.Context, plan string) (result map[string]any, err error) {
	plan = controlPath(plan)
	if !filepath.IsAbs(plan) || filepath.Base(plan) != "2026-10-28-uup-builder-remaining-work-plan" {
		return nil, errors.New("exact plan namespace required")
	}
	parent := filepath.Join(plan, "r3a2b")
	if err = os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	bundle, err := platform.CreateWorkspace(parent, "desktop-control")
	if err != nil {
		return nil, err
	}
	defer bundle.Close()
	store, err := jobstore.Create(parent, "desktop-control", nil)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	provider, err := platform.CreateWorkspace(parent, "desktop-control")
	if err != nil {
		return nil, err
	}
	defer provider.Close()
	apply, err := platform.CreateWorkspace(parent, "desktop-control")
	if err != nil {
		return nil, err
	}
	defer apply.Close()
	for _, dir := range []string{"logs", "tmp"} {
		if err = provider.MkdirAll(dir); err != nil {
			return nil, err
		}
	}
	if err = apply.MkdirAll("image"); err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	src, err := controlReadLock(self, false)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	dst, err := bundle.OpenFile("runner.exe", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	err = controlCopy(dst, src)
	err = errors.Join(err, dst.Close())
	if err != nil {
		return nil, err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	r := controlRequest{Version: 1, Profile: controlProfile, Plan: plan, Source: filepath.Join(plan, "native-control", "source", "desktop-control.esd"), Tool: filepath.Join(system, "dism.exe"), Runner: controlPath(filepath.Join(bundle.Path(), "runner.exe")), Bundle: bundle.Identity(), Store: store.Identity(), Provider: provider.Identity(), Apply: apply.Identity()}
	for i, id := range []platform.WorkspaceIdentity{r.Bundle, r.Store, r.Provider, r.Apply} {
		f, e := controlReadLock(id.Path, true)
		if e != nil {
			return nil, e
		}
		r.ScopeIDs[i], e = controlDirectoryID(f)
		f.Close()
		if e != nil {
			return nil, e
		}
	}
	proposal, err := controlProposal(r)
	if err != nil {
		return nil, err
	}
	facts, locks, err := measureControl(ctx, r)
	defer closeControlFiles(locks)
	if err != nil {
		return nil, err
	}
	r.Facts = facts
	if err = validateControl(r, facts, false); err != nil {
		return nil, err
	}
	baseline, err := inspectControlSource(r.Plan)
	if err != nil {
		return nil, err
	}
	if err = assertControlBaseline(baseline); err != nil {
		return nil, err
	}
	for name, expect := range controlSourceHives {
		if baseline.Hives[name] != expect.SHA {
			return nil, errors.New("retained source hive identity changed")
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if err = controlSync(bundle, "request.json", b, true); err != nil {
		return nil, err
	}
	request := controlPath(filepath.Join(bundle.Path(), "request.json"))
	sha := controlHash(b)
	result = map[string]any{"state": "prepared-no-native-execution", "profile": controlProfile, "runner": r.Runner, "runner_sha256": facts.Runner.SHA256, "request": request, "request_sha256": sha, "source": r.Source, "facts": facts, "source_hives": baseline, "store": controlPath(r.Store.Path), "provider": controlPath(r.Provider.Path), "apply": controlPath(r.Apply.Path), "path_rule": "fresh J1 scratch/<32-hex>/fixed-leaf; exact paths synced before launch", "action": controlAction(r.Runner, request, sha, "run"), "recovery_inspection": controlAction(r.Runner, request, sha, "recover-inspect"), "recovery_discard": controlAction(r.Runner, request, sha, "recover-discard")}
	tokenObservation, e := observeControlToken()
	if e != nil {
		return nil, e
	}
	result["preparation_token"] = tokenObservation
	result["operation_proposal"] = proposal
	if err = controlJSON(bundle, "preparation.json", result, true); err != nil {
		return nil, err
	}
	return result, nil
}
func controlAction(exe, request, sha, mode string) []string {
	return []string{exe, "-test.run=^TestNativeControlPrivate$", "-test.timeout=0", "-test.v", "-control-mode=" + mode, "-control-request=" + request, "-control-sha=" + sha}
}

// This private test process runs exactly one fixed action. Only its own child
// environment changes; no persistent user/machine environment is written.
func controlTemp(provider string) (func() error, error) {
	keys := []string{"TEMP", "TMP"}
	old := map[string]string{}
	exists := map[string]bool{}
	for _, key := range keys {
		old[key], exists[key] = os.LookupEnv(key)
	}
	restore := func() error {
		var err error
		for _, key := range keys {
			if exists[key] {
				err = errors.Join(err, os.Setenv(key, old[key]))
			} else {
				err = errors.Join(err, os.Unsetenv(key))
			}
		}
		return err
	}
	for _, key := range keys {
		if err := os.Setenv(key, filepath.Join(controlPath(provider), "tmp")); err != nil {
			return nil, errors.Join(err, restore())
		}
	}
	return restore, nil
}
func closeControlFiles(files []*os.File) {
	for i := len(files) - 1; i >= 0; i-- {
		files[i].Close()
	}
}
func measureControl(ctx context.Context, r controlRequest) (a controlFacts, locks []*os.File, err error) {
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return a, locks, err
	}
	peer, err := platform.CurrentPeerIdentity()
	if err != nil {
		return a, locks, err
	}
	a.Build = host.WindowsBuild
	a.Native = string(host.NativeArchitecture)
	a.Process = string(host.ProcessArchitecture)
	a.SID = peer.UserSID
	a.Elevated = peer.Elevated
	for _, item := range []struct {
		path           string
		dst            *controlPin
		binary, source bool
	}{{r.Source, &a.Source, false, true}, {r.Tool, &a.Tool, true, false}, {r.Runner, &a.Runner, true, false}} {
		var f *os.File
		var e error
		if item.dst == &a.Tool {
			f, e = controlComponentReadLock(item.path)
		} else {
			f, e = controlReadLock(item.path, false)
		}
		if e != nil {
			return a, locks, e
		}
		locks = append(locks, f)
		*item.dst, e = controlPinFile(f, item.binary, item.source)
		if e != nil {
			return a, locks, e
		}
	}
	a.Tool.Versions, err = controlVersions(r.Tool)
	if err != nil {
		return a, locks, err
	}
	a.Free, err = controlFree(r.Store.Path)
	return a, locks, err
}
func inspectControlSource(plan string) (controlObservation, error) {
	return inspectControlHives(func(name string) (*os.File, error) {
		return controlReadLock(filepath.Join(plan, "native-control", "source", "solid-members-001", controlSourceHives[name].File), false)
	})
}
func inspectControlTree(w *platform.Workspace, root string) (controlObservation, error) {
	return inspectControlHives(func(name string) (*os.File, error) {
		return w.OpenFile(filepath.ToSlash(filepath.Join(root, controlHiveMembers[name])), os.O_RDONLY, 0)
	})
}
