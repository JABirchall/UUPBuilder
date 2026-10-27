package probes

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type ObservationDescriptor struct {
	Case    Case          `json:"case"`
	Runtime RuntimeConfig `json:"runtime"`
}

func LoadObservation(r io.Reader, fixtureRoot, workspaceParent string) (ObservationDescriptor, error) {
	var d ObservationDescriptor
	b, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return d, err
	}
	if len(b) > 1<<20 {
		return d, errors.New("observation descriptor exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return d, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return d, errors.New("observation descriptor trailing data")
	}
	d.Runtime.FixtureRoot = fixtureRoot
	d.Runtime.WorkspaceParent = workspaceParent
	_, err = validateRuntime(d.Case, d.Runtime)
	return d, err
}
