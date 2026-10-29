package planner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/pelletier/go-toml/v2"
	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
)

func hash(v any) string {
	// TOML has no null array. Treat nil and empty collections identically so
	// exact validated identities survive the public TOML representation.
	b, _ := json.Marshal(v)
	var canonical any
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	_ = decoder.Decode(&canonical)
	canonical = normalize(canonical)
	b, _ = json.Marshal(canonical)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func normalize(v any) any {
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			return nil
		}
		for i := range x {
			x[i] = normalize(x[i])
		}
	case map[string]any:
		for key, value := range x {
			x[key] = normalize(value)
		}
	}
	return v
}
func copyOf[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out T
	if err = json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}
func freeze(f frozen) ReadyPlan {
	owned := copyOf(f)
	return ReadyPlan{data: &owned, digest: hash(owned)}
}
func (p ReadyPlan) Selection() model.Selection {
	if p.data == nil {
		return model.Selection{}
	}
	return copyOf(p.data.Selection)
}
func (p ReadyPlan) RequestedSettings() model.ResolvedSettings {
	if p.data == nil {
		return model.ResolvedSettings{}
	}
	return copyOf(p.data.Requested)
}
func (p ReadyPlan) EffectiveSettings() model.ResolvedSettings {
	if p.data == nil {
		return model.ResolvedSettings{}
	}
	return copyOf(p.data.Effective)
}
func (p ReadyPlan) Manifest() model.PayloadManifest {
	if p.data == nil {
		return model.PayloadManifest{}
	}
	return copyOf(p.data.Manifest)
}
func (p ReadyPlan) Operations() []Operation {
	if p.data == nil {
		return nil
	}
	return copyOf(p.data.Operations)
}
func (p ReadyPlan) Tools() []tools.Requirement {
	if p.data == nil {
		return nil
	}
	return copyOf(p.data.Tools)
}
func (p ReadyPlan) Applicability() []model.SettingApplicability {
	if p.data == nil {
		return nil
	}
	return copyOf(p.data.Applicability)
}
func (p ReadyPlan) DraftRevision() uint64 {
	if p.data == nil {
		return 0
	}
	return p.data.DraftRevision
}
func (p ReadyPlan) Intent() JobIntent {
	if p.data == nil {
		return ""
	}
	return p.data.Intent
}
func (p ReadyPlan) Digest() string { return p.digest }
func (p ReadyPlan) Estimates() Estimate {
	if p.data == nil {
		return Estimate{}
	}
	return p.data.Estimate
}
func (p ReadyPlan) StorageChecks() []StorageCheck {
	if p.data == nil {
		return nil
	}
	return copyOf(p.data.Storage)
}

// Validate checks the sealed content and the only graph shape this version can
// authorize. A digest is an identity, not authority from an untrusted sender.
func (p ReadyPlan) Validate() error {
	if p.data == nil {
		return ErrInvalidPlan
	}
	f := p.data
	if p.digest != hash(*f) {
		return ErrIdentityChanged
	}
	if f.Version != 1 || f.Selection.Validate() != nil || f.Requested.Validate() != nil || f.Effective.Validate() != nil || f.Manifest.Validate() != nil {
		return ErrInvalidPlan
	}
	if f.Intent != BuildMedia && f.Intent != DownloadOnly {
		return ErrInvalidPlan
	}
	if f.Host.WindowsBuild < 10240 || f.Host.NativeArchitecture.Validate() != nil || f.Host.ProcessArchitecture.Validate() != nil {
		return ErrInvalidPlan
	}
	if f.Intent == BuildMedia && f.AppPhase != "offline-provisioning" && f.AppPhase != "post-assembly" {
		return ErrInvalidPlan
	}
	if f.Manifest.Source.UpdateID != f.Selection.UpdateID || f.Manifest.Source.Architecture != f.Selection.Architecture || f.Manifest.Source.Language != f.Selection.Language {
		return ErrInvalidPlan
	}
	requested := f.Requested
	if requested.Storage.Workspace == "auto" {
		requested.Storage.Workspace = f.Effective.Storage.Workspace
	}
	if requested.Storage.Cache == "auto" {
		requested.Storage.Cache = f.Effective.Storage.Cache
	}
	if !reflect.DeepEqual(requested, f.Effective) {
		return ErrInvalidPlan
	}
	if _, err := settingsApplicability(f.Requested); err != nil {
		return err
	}
	if (model.Digest{Algorithm: model.DigestSHA256, Value: f.InventoryDigest}).Validate() != nil {
		return ErrInvalidPlan
	}
	for _, r := range f.Tools {
		if r.Validate() != nil || !reflect.DeepEqual(r.Host, f.Host) || r.Target != f.Selection.Architecture {
			return ErrInvalidPlan
		}
		manifest, err := tools.DefaultManifest()
		if err != nil {
			return err
		}
		if r.ManifestDigest != manifest.Digest() || hash(r.Operations) != hash([]tools.Operation{tools.Extract, tools.Inspect, tools.Reconstruct, tools.Service, tools.MasterISO}) {
			return ErrInvalidPlan
		}
	}
	if (f.Intent == DownloadOnly && len(f.Tools) != 0) || (f.Intent == BuildMedia && len(f.Tools) != 1) {
		return ErrInvalidPlan
	}
	if hash(f.Operations) != hash(graph(*f)) {
		return fmt.Errorf("%w: operation graph", ErrInvalidPlan)
	}
	if len(f.Storage) != 3 {
		return ErrInvalidPlan
	}
	index := 0
	checker := Planner{InspectStorage: func(_ context.Context, path string) (Volume, error) {
		v := f.Storage[index].Volume
		index++
		return v, nil
	}}
	estimate, checks, err := checker.space(context.Background(), Request{Settings: f.Effective, Resolution: source.Resolution{Manifest: f.Manifest}, Intent: f.Intent})
	if err != nil || hash(estimate) != hash(f.Estimate) || hash(checks) != hash(f.Storage) {
		return ErrInvalidPlan
	}
	return nil
}
func (p ReadyPlan) MarshalTOML() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return toml.Marshal(struct {
		Digest string
		Plan   frozen
	}{p.digest, *p.data})
}
func DecodeReadyPlan(data []byte) (ReadyPlan, error) {
	if len(data) == 0 || len(data) > 8<<20 {
		return ReadyPlan{}, ErrInvalidPlan
	}
	var doc struct {
		Digest string
		Plan   frozen
	}
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return ReadyPlan{}, fmt.Errorf("%w: invalid TOML envelope", ErrInvalidPlan)
	}
	if doc.Digest != hash(doc.Plan) {
		return ReadyPlan{}, ErrIdentityChanged
	}
	p := freeze(doc.Plan)
	if err := p.Validate(); err != nil {
		return ReadyPlan{}, err
	}
	return p, nil
}
