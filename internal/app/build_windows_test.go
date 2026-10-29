package app

import (
	"context"
	"strings"
	"testing"

	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
	"uupbuilder/internal/tui"
)

func TestDefaultBuildReportsMissingDiscoveryWithoutMutation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision"
	cfg.Output.Directory = t.TempDir()
	opts := Options{Config: cfg}
	closeBuild := composeInteractiveBuild(&opts)
	defer closeBuild()
	_, err := opts.Dependencies.Builder.Prepare(context.Background(), tui.BuildDraft{Config: cfg, Revision: 4})
	if err == nil || !strings.Contains(err.Error(), "metadata-discovery-unavailable") {
		t.Fatalf("missing producer: %v", err)
	}
	cfg.Output.Kind = model.OutputDirectory
	_, err = opts.Dependencies.Builder.Prepare(context.Background(), tui.BuildDraft{Config: cfg, Revision: 5})
	if err == nil || !strings.Contains(err.Error(), "output.kind") {
		t.Fatalf("explicit excluded setting: %v", err)
	}
}
func TestPrivateWorkerModeRejectsMalformedBootstrap(t *testing.T) {
	handled, err := runPrivateWorker(context.Background(), []string{"--uup-worker", "invalid"})
	if !handled || err == nil {
		t.Fatalf("private mode reached interactive config path: %v %v", handled, err)
	}
}
