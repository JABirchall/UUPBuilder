package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tui"
)

// Headless mode uses the same preparation, frozen planner, registry, controller
// and private publication boundary as the Workspace. It never requests UAC.
func runHeadlessBuild(ctx context.Context, args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--build-iso" && args[0] != "--plan-iso" {
		return false, nil
	}
	execute := args[0] == "--build-iso"
	if execute {
		peer, err := platform.CurrentPeerIdentity()
		if err != nil {
			return true, err
		}
		if !peer.Elevated {
			return true, fmt.Errorf("offline ISO servicing requires an already elevated worker; run this same --build-iso --config command from an authorized administrator terminal (no elevation or installation was launched)")
		}
	}
	return true, run(ctx, args[1:], func(ctx context.Context, opts Options) (resultErr error) {
		closeBuild, err := composeInteractiveBuild(&opts)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, closeBuild()) }()
		fmt.Fprintln(os.Stderr, "Preparing exact selected source, app metadata and managed runtime...")
		plan, err := opts.Dependencies.Builder.Prepare(ctx, tui.BuildDraft{Config: opts.Config, Revision: 1})
		if err != nil {
			return err
		}
		if !execute {
			return json.NewEncoder(os.Stdout).Encode(struct {
				PlanDigest             string
				Operations             int
				RequiresElevatedWorker bool
			}{plan.Digest(), len(plan.Operations()), true})
		}
		result, err := opts.Dependencies.Builder.Execute(ctx, plan)
		if err != nil {
			return err
		}
		if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if result.Error != "" {
			return fmt.Errorf("ISO job %s: %s", result.JobID, result.Error)
		}
		return nil
	})
}
