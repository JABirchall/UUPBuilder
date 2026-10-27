package tui

import (
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

// Selection messages accept only values returned by catalogue discovery;
// titles/build numbers are never substitutes for an exact upstream ID.
type NavigateMsg struct{ Area Area }
type SearchChangedMsg struct{ Query string }
type SelectBuildMsg struct{ UpdateID string }
type ChangeArchitectureMsg struct{ Architecture model.Architecture }
type SelectLanguageMsg struct{ Language string }
type ToggleEditionMsg struct{ Edition string }
type RefreshMsg struct{}
type initializeMsg struct{}
type imageFocusMsg struct{ field int }
type editionClickMsg struct {
	index   int
	edition string
}
type searchDebouncedMsg struct {
	generation uint64
	query      string
}
type searchResultMsg struct {
	generation uint64
	query      string
	builds     []catalog.Build
	err        error
	checkedAt  time.Time
}
type languagesResultMsg struct {
	generation uint64
	updateID   string
	languages  []catalog.Language
	err        error
	checkedAt  time.Time
}
type editionsResultMsg struct {
	generation         uint64
	updateID, language string
	editions           []catalog.Edition
	err                error
	checkedAt          time.Time
}
