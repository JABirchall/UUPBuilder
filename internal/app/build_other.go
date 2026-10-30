//go:build !windows

package app

import (
	"context"
	"errors"
)

func composeInteractiveBuild(opts *Options) (func() error, error) {
	return closeBuildService(opts.Dependencies.Builder), nil
}
func runPrivateWorker(_ context.Context, args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--uup-worker" {
		return false, nil
	}
	return true, errors.New("restricted worker requires Windows")
}
