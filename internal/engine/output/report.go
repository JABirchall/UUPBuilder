package output

import (
	"encoding/json"
	"io"
	"uupbuilder/internal/model"
)

type reportSettings struct {
	ImageFormat model.ImageFormat     `json:"image_format"`
	Editions    []string              `json:"editions"`
	Apps        model.AppSettings     `json:"apps"`
	Updates     model.UpdatePolicy    `json:"updates"`
	Cleanup     bool                  `json:"cleanup"`
	ResetBase   model.ResetBasePolicy `json:"reset_base"`
	NetFX3      bool                  `json:"netfx3"`
}

// The report is an allowlist of identities. It never serializes configuration,
// download locators, proxy credentials, private workspaces or helper arguments.
func writeReport(w io.Writer, a model.Artifact, verified *verifiedState) error {
	return json.NewEncoder(w).Encode(struct {
		Version    int                  `json:"version"`
		Source     model.SourceIdentity `json:"source"`
		PlanDigest string               `json:"plan_digest"`
		Size       int64                `json:"size"`
		SHA256     string               `json:"sha256"`
		Checks     map[string]string    `json:"checks"`
		Settings   reportSettings       `json:"settings"`
		Tools      []ToolIdentity       `json:"tools"`
	}{1, a.Source, a.PlanDigest, a.Size, a.SHA256, map[string]string{
		"local_iso_contents": "verified", "destination_bytes": "verified", "recovery": "excluded", "boot_execution": "excluded", "setup_execution": "excluded", "physical_media": "excluded",
	}, verified.settings, verified.tools})
}
