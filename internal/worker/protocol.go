//go:build windows

// Package worker authorizes fixed handlers against an active immutable plan.
package worker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

type OperationRequest struct {
	Version     uint32
	JobID       string
	PlanDigest  string
	Workspace   platform.WorkspaceIdentity
	Capability  string
	Intent      planner.JobIntent
	OperationID string
}
type PlanEnvelope struct{ TOML []byte }
type OperationResponse struct {
	OperationID      string
	CheckpointDigest string
	Error            string
}

func RequestFor(d platform.WorkerDescriptor, intent planner.JobIntent, operation string) OperationRequest {
	return OperationRequest{Version: 1, JobID: d.JobID, PlanDigest: d.PlanDigest, Workspace: d.Workspace, Capability: d.Workspace.Token, Intent: intent, OperationID: operation}
}

const maxFrameBytes = 12 << 20

func ReadFrame(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxFrameBytes {
		return errors.New("invalid worker frame size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	if err := uniqueKeys(b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.New("invalid worker frame")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing worker frame")
	}
	return nil
}
func WriteFrame(w io.Writer, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(b) == 0 || len(b) > maxFrameBytes {
		return errors.New("invalid worker frame size")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if _, err = w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
func uniqueKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("worker frame nesting limit")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate worker field")
				}
				seen[s] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing worker frame")
	}
	return nil
}
