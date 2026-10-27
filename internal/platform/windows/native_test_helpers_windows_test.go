package windows

import (
	"context"
	"encoding/binary"
	"net/http"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Junctions are unprivileged filesystem reparse points. No symlink privilege,
// command interpreter, downloaded helper, or system mount is used here.
func createJunction(t *testing.T, path, target string) {
	t.Helper()
	p, _ := windows.UTF16PtrFromString(path)
	if err := windows.CreateDirectory(p, nil); err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	sub := utf16.Encode([]rune(`\??\` + target))
	printName := utf16.Encode([]rune(target))
	data := make([]byte, 16+2*(len(sub)+1+len(printName)+1))
	binary.LittleEndian.PutUint32(data, windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(data[4:], uint16(len(data)-8))
	binary.LittleEndian.PutUint16(data[10:], uint16(2*len(sub)))
	binary.LittleEndian.PutUint16(data[12:], uint16(2*(len(sub)+1)))
	binary.LittleEndian.PutUint16(data[14:], uint16(2*len(printName)))
	buf := unsafe.Slice((*uint16)(unsafe.Pointer(&data[16])), (len(data)-16)/2)
	copy(buf, sub)
	copy(buf[len(sub)+1:], printName)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &n, nil); err != nil {
		t.Fatal(err)
	}
}

type httpHandlerPAC struct{}

func (httpHandlerPAC) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Write([]byte(`function FindProxyForURL(url,host) { if (host == "one.example") return "PROXY 127.0.0.1:3128"; return "DIRECT"; }`))
}

type nativeProxyWithConfig struct{ c proxyConfig }

func (p nativeProxyWithConfig) configuration() (proxyConfig, error) { return p.c, nil }
func (p nativeProxyWithConfig) resolve(ctx context.Context, target string, c proxyConfig) (proxyDecision, error) {
	return (nativeProxy{}).resolve(ctx, target, c)
}

func assertPrivateDACL(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("object inherits ambient parent permissions")
	}
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatal("object has no restrictive DACL")
	}
	found := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (sid != self.UserSID && sid != "S-1-5-18") {
			t.Fatalf("unexpected DACL principal/type %s/%d", sid, ace.Header.AceType)
		}
		found[sid] = true
	}
	if !found[self.UserSID] || !found["S-1-5-18"] {
		t.Fatal("owner/SYSTEM access missing")
	}
}
