package windows

import (
	"context"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPipeRejectsUnauthorizedPeer(t *testing.T) {
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPipeServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wrong := self
	wrong.ProcessID++
	done := make(chan error, 1)
	go func() {
		c, e := server.Accept(ctx, wrong)
		if c != nil {
			c.Close()
		}
		done <- e
	}()
	client, err := DialWorkerPipe(ctx, server.Name(), self)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-done; err == nil {
		t.Fatal("accepted a different process with the same user")
	}
}

func TestNativePipeAuthenticatesBothEndsAndTransfersBytes(t *testing.T) {
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPipeServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, e := server.Accept(ctx, self)
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		b := make([]byte, 5)
		_, e = io.ReadFull(c, b)
		if e == nil && string(b) != "hello" {
			e = io.ErrUnexpectedEOF
		}
		if e == nil {
			_, e = c.Write([]byte("world"))
		}
		done <- e
	}()
	c, err := DialWorkerPipe(ctx, server.Name(), self)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "world" {
		t.Fatalf("reply %q", b)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPipeCancellationAndPeerIdentityMismatch(t *testing.T) {
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PeerIdentity){func(p *PeerIdentity) { p.UserSID = "S-1-5-18" }, func(p *PeerIdentity) { p.SessionID++ }, func(p *PeerIdentity) { p.CreationTime++ }, func(p *PeerIdentity) { p.Elevated = !p.Elevated }, func(p *PeerIdentity) { p.Executable += ".other" }} {
		other := self
		mutate(&other)
		if err := authorizePeer(self, other); err == nil {
			t.Fatalf("accepted mismatch %#v", other)
		}
	}
	server, err := NewPipeServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := server.Accept(ctx, self); err == nil {
		t.Fatal("accept ignored cancellation")
	}
}

func TestPipeCloseInterruptsPendingAccept(t *testing.T) {
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPipeServer()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := server.Accept(context.Background(), self); done <- err }()
	time.Sleep(20 * time.Millisecond)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed server accepted a client")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt pending accept")
	}
}

func TestPipeUsesRestrictedNativeDACL(t *testing.T) {
	server, err := NewPipeServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	sd, err := windows.GetSecurityInfo(server.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivateDACL(t, sd)
}
