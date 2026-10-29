//go:build windows

package worker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

func TestWorkerRejectsUnknownMountStateBeforeMutation(t *testing.T) {
	plan, store, peer, d := workerFixture(t)
	store.Close()
	reopened, err := jobstore.Open(d.Workspace, incompleteMounts{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	registry := NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, Handler{Run: func(context.Context, Stage) (Result, error) {
		t.Error("handler ran without actual mount inventory")
		return Result{}, errors.New("handler reached")
	}})
	session, err := NewSession(plan, d, peer, peer, reopened, registry)
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Dispatch(context.Background(), peer, RequestFor(d, plan.Intent(), plan.Operations()[0].ID))
	if err == nil || !strings.Contains(err.Error(), "preserved") {
		t.Fatalf("unknown mount state did not block: %v", err)
	}
}

type incompleteMounts struct{}

func (incompleteMounts) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{}, nil
}

func TestAuthenticatedWorkerCustodyTransfer(t *testing.T) {
	plan, store, peer, d := workerFixture(t)
	registry := NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, Handler{Run: resultHandler})
	encoded, err := plan.MarshalTOML()
	if err != nil {
		t.Fatal(err)
	}
	for _, release := range []bool{false, true} {
		t.Run(map[bool]string{false: "concurrent-writer-blocked", true: "released-writer-succeeds"}[release], func(t *testing.T) {
			if release {
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			server, err := platform.NewPipeServer()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := server.Accept(ctx, peer)
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				done <- Serve(ctx, platform.WorkerBootstrap{Descriptor: d, PipeName: server.Name(), Parent: peer}, conn, registry, clearMounts{})
			}()
			client, err := platform.DialWorkerPipe(ctx, server.Name(), peer)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := WriteFrame(client, PlanEnvelope{TOML: encoded}); err != nil {
				t.Fatal(err)
			}
			if !release {
				if err := <-done; err == nil || !strings.Contains(err.Error(), "writer already owned") {
					t.Fatalf("concurrent custody: %v", err)
				}
				return
			}
			if err := WriteFrame(client, RequestFor(d, plan.Intent(), plan.Operations()[0].ID)); err != nil {
				t.Fatal(err)
			}
			var response OperationResponse
			if err := ReadFrame(client, &response); err != nil {
				t.Fatal(err)
			}
			if response.Error != "" || len(response.CheckpointDigest) != 64 {
				t.Fatalf("authorized response: %#v", response)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestWorkerProtocolRejectsCommandsAndAmbiguousFrames(t *testing.T) {
	for _, body := range []string{`{"OperationID":"download-payloads","Command":"cmd.exe"}`, `{"OperationID":"a","OperationID":"b"}`, `{"Intent":"download-only"} {"Intent":"build-media"}`} {
		var frame bytes.Buffer
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(body)))
		frame.Write(header[:])
		frame.WriteString(body)
		if err := ReadFrame(&frame, new(OperationRequest)); err == nil {
			t.Fatalf("accepted untrusted frame %s", body)
		}
	}
}
