//go:build !windows

package app

import (
	"context"
	"errors"
)

func composeInteractiveBuild(*Options) func() { return func() {} }
func runPrivateWorker(_ context.Context, args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--uup-worker" {
		return false, nil
	}
	return true, errors.New("restricted worker requires Windows")
}
