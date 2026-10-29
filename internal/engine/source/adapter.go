package source

import (
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Normalize requires verified tools, prepared predecessor custody and an active
// transaction in U07. This prerequisite implements only the planning contracts;
// there is deliberately no placeholder Normalize returning an accepted source.
type Adapter interface {
	Match(metadata.Inventory) (Match, error)
	Recipe(metadata.Inventory, model.ResolvedSettings) (Recipe, error)
}
