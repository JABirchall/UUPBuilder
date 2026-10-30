package metadata

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"uupbuilder/internal/model"
)

type UpdateKind string

const (
	UpdateServicingStack UpdateKind = "servicing-stack"
	UpdateCheckpoint     UpdateKind = "checkpoint"
	UpdateCumulative     UpdateKind = "cumulative"
	UpdateEnablement     UpdateKind = "enablement"
)

type UpdateFormat string

const (
	UpdateCAB UpdateFormat = "cab"
	UpdateMSU UpdateFormat = "msu"
)

// Update is an inspected applicability/dependency assertion, never a filename
// heuristic. Packages are exact CBS identities expected after servicing. Members
// lists MSU CABs in their inspected installation order when expansion is needed.
type Update struct {
	ID           string
	Kind         UpdateKind
	Format       UpdateFormat
	Resource     ResourceReference
	Packages     []PackageIdentity
	Predecessors []string
	Editions     []string
	Members      []string
	Evidence     Evidence
}

func (inv *Inventory) applyUpdates(updates []Update, known map[model.PayloadIdentity]bool) error {
	for _, update := range updates {
		if strings.TrimSpace(update.ID) == "" || !validReference(update.Resource, known) || inv.validateEvidence(update.Evidence) != nil || len(update.Packages) == 0 {
			return fmt.Errorf("%w: update identity/resource/evidence", ErrInvalidEvidence)
		}
		switch update.Kind {
		case UpdateServicingStack, UpdateCheckpoint, UpdateCumulative, UpdateEnablement:
		default:
			return ErrInvalidEvidence
		}
		if update.Format != UpdateCAB && update.Format != UpdateMSU {
			return ErrInvalidEvidence
		}
		for _, pack := range update.Packages {
			if pack.Name == "" || pack.Version == "" || pack.Architecture.Validate() != nil {
				return ErrInvalidEvidence
			}
		}
		for _, member := range update.Members {
			if !validMember(member) || !strings.EqualFold(filepath.Ext(member), ".cab") {
				return ErrInvalidEvidence
			}
		}
		for _, old := range inv.Updates {
			if strings.EqualFold(old.ID, update.ID) {
				return ErrConflictingMetadata
			}
		}
		update.Packages = slices.Clone(update.Packages)
		update.Predecessors = slices.Clone(update.Predecessors)
		update.Editions = slices.Clone(update.Editions)
		update.Members = slices.Clone(update.Members)
		inv.Updates = append(inv.Updates, update)
	}
	return nil
}
