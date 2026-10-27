//go:build !windows

package probes

func newRuntimePorts(observe func() (ObservedHost, error)) runtimePorts {
	return runtimePorts{observe: observe, kind: "unsupported-host"}
}
