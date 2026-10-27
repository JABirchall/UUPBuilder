//go:build !windows

package probes

import (
	"errors"
	"runtime"

	"uupbuilder/internal/model"
)

func observeHost() (ObservedHost, error) {
	return ObservedHost{OS: runtime.GOOS, Host: model.Host{ProcessArchitecture: model.ArchitectureFromGo(runtime.GOARCH)}}, errors.New("actual native Windows host unavailable; compilation on another OS is not runtime evidence")
}
