//go:build !windows

package app

import "context"

func runHeadlessBuild(ctx context.Context, args []string) (bool, error) { return false, nil }
