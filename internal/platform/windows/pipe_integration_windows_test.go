//go:build windows && windowsintegration

package windows

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsIntegrationPipeAuthenticatesSelfBuiltSubprocess(t *testing.T) {
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPipeServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	exe, _ := os.Executable()
	b, _ := json.Marshal(self)
	child := exec.Command(exe, "-test.run=^TestPlatformHelper$", "--", "--w1-helper", "pipe-client", server.Name(), base64.RawURLEncoding.EncodeToString(b))
	child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	expected, handle, err := inspectPeer(uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := server.Accept(ctx, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b = make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatalf("request %q", b)
	}
	if _, err := c.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
}
