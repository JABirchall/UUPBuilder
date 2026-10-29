package probes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	platform "uupbuilder/internal/platform/windows"
)

type controlProcessParent struct{ PID, Parent uint32 }

func controlDescendants(root uint32, processes []controlProcessParent, retained ...uint32) map[uint32]bool {
	out := map[uint32]bool{root: true}
	for _, pid := range retained {
		out[pid] = true
	}
	for i := 0; i < len(processes); i++ {
		changed := false
		for _, p := range processes {
			if out[p.Parent] && !out[p.PID] {
				out[p.PID] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return out
}

type controlModuleFact struct {
	PID                 uint32
	Creation            uint64
	Path                string
	Pin                 controlPin
	VersionError, Error string
}
type controlProcessFact struct {
	PID, Parent uint32
	Creation    uint64
	Path        string
	Error       string
}
type controlObserver struct {
	mu        sync.Mutex
	processes []controlProcessFact
	modules   []controlModuleFact
	errors    []string
	seen      map[string]bool
}

func (o *controlObserver) sample() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.errors) > 64 {
		return
	}
	if o.seen == nil {
		o.seen = map[string]bool{}
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		o.errors = append(o.errors, err.Error())
		return
	}
	defer windows.CloseHandle(snap)
	var list []controlProcessParent
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		list = append(list, controlProcessParent{entry.ProcessID, entry.ParentProcessID})
		if len(list) > 16384 {
			o.errors = append(o.errors, "process snapshot limit")
			return
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		o.errors = append(o.errors, err.Error())
		return
	}
	// A retained helper may outlive its direct parent. Revalidate its process
	// creation time before seeding a new snapshot, avoiding PID reuse adoption.
	var retained []uint32
	for _, prior := range o.processes {
		if prior.Creation == 0 || prior.Error != "" {
			continue
		}
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, prior.PID)
		if e != nil {
			continue
		}
		var create, exit, kernel, user windows.Filetime
		e = windows.GetProcessTimes(h, &create, &exit, &kernel, &user)
		windows.CloseHandle(h)
		if e == nil && uint64(create.HighDateTime)<<32|uint64(create.LowDateTime) == prior.Creation {
			retained = append(retained, prior.PID)
		}
	}
	owned := controlDescendants(uint32(os.Getpid()), list, retained...)
	for _, p := range list {
		if p.PID == uint32(os.Getpid()) || !owned[p.PID] {
			continue
		}
		if len(o.processes) >= 512 {
			o.errors = append(o.errors, "owned process observation limit")
			return
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
		if err != nil {
			o.errors = append(o.errors, err.Error())
			continue
		}
		var create, exit, kernel, user windows.Filetime
		var creation uint64
		if err = windows.GetProcessTimes(h, &create, &exit, &kernel, &user); err == nil {
			creation = uint64(create.HighDateTime)<<32 | uint64(create.LowDateTime)
		}
		path := make([]uint16, 32768)
		size := uint32(len(path))
		if err == nil {
			err = windows.QueryFullProcessImageName(h, 0, &path[0], &size)
		}
		windows.CloseHandle(h)
		fact := controlProcessFact{PID: p.PID, Parent: p.Parent, Creation: creation, Path: windows.UTF16ToString(path[:size])}
		if err != nil {
			fact.Error = err.Error()
		}
		key := stringKey(fact.PID, fact.Creation, fact.Path)
		if !o.seen[key] {
			o.seen[key] = true
			o.processes = append(o.processes, fact)
		}
		if creation == 0 || err != nil {
			continue
		}
		mods, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, p.PID)
		if e != nil {
			o.errors = append(o.errors, e.Error())
			continue
		}
		module := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
		for e = windows.Module32First(mods, &module); e == nil; e = windows.Module32Next(mods, &module) {
			if len(o.modules) >= 4096 {
				o.errors = append(o.errors, "module observation limit")
				break
			}
			path := windows.UTF16ToString(module.ExePath[:])
			key := stringKey(p.PID, creation, path)
			if o.seen["module:"+key] {
				continue
			}
			o.seen["module:"+key] = true
			m := controlModuleFact{PID: p.PID, Creation: creation, Path: path}
			f, readErr := controlComponentReadLock(path)
			if readErr == nil {
				if st, e := f.Stat(); e != nil || st.Size() > 128<<20 {
					readErr = errors.New("module size/inspection bound")
				} else {
					m.Pin, readErr = controlPinFile(f, true, false)
				}
				f.Close()
			}
			if readErr != nil {
				m.Error = readErr.Error()
			}
			m.Pin.Versions, readErr = controlVersions(path)
			if readErr != nil {
				m.VersionError = readErr.Error()
			}
			o.modules = append(o.modules, m)
		}
		windows.CloseHandle(mods)
		if e != nil && !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
			o.errors = append(o.errors, e.Error())
		}
	}
}
func stringKey(pid uint32, creation uint64, path string) string {
	return fmtControlIdentity(pid, creation) + ":" + path
}
func fmtControlIdentity(pid uint32, creation uint64) string {
	return fmt.Sprintf("%d:%d", pid, creation)
}
func (o *controlObserver) observe(ctx context.Context, provider *platform.Workspace) func() error {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTicker(100 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-timer.C:
				o.sample()
			}
		}
	}()
	return func() error {
		close(stop)
		<-done
		o.sample()
		o.mu.Lock()
		defer o.mu.Unlock()
		return controlJSON(provider, "modules.json", map[string]any{"kind": "sampled-owned-descendants-incomplete-closure", "processes": o.processes, "modules": o.modules, "errors": o.errors, "limits": "100ms sampling may miss short-lived processes; service-hosted components/resources may be absent; full provider acceptance unverified"}, false)
	}
}
