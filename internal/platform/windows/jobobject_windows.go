package windows

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Each invocation has a distinct unnamed, non-inheritable job. No process-name
// search, PID-tree walk, global job, or breakaway permission is used.
func newOwnedJob() (windows.Handle, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}
