//go:build windows && nativecontrol

package probes

import (
	"context"
	"encoding/json"
	"flag"
	"golang.org/x/sys/windows"
	"os"
	"os/signal"
	"path/filepath"
	"testing"
)

var controlMode = flag.String("control-mode", "", "private fixed control: prepare, run, recover-inspect, recover-discard")
var controlPlan = flag.String("control-plan", "", "private plan namespace for non-admin preparation")
var controlRequestPath = flag.String("control-request", "", "exact private prepared request path")
var controlRequestSHA = flag.String("control-sha", "", "SHA256 of exact prepared request bytes")

func TestNativeControlPrivate(t *testing.T) {
	if *controlMode == "" {
		t.Skip("private fixed control not requested")
	}
	if *controlMode == "prepare" {
		result, err := prepareControl(context.Background(), *controlPlan)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		t.Log(string(b))
		return
	}
	// Go's ordinary test timeout force-terminates the entire process and would
	// bypass CancelWait. Privileged fixed actions reject that unsafe harness.
	if flag.Lookup("test.timeout").Value.String() != "0s" {
		t.Fatal("native control requires -test.timeout=0 for safe mutation cancellation")
	}
	if *controlRequestPath == "" || *controlRequestSHA == "" {
		t.Fatal("sealed prepared request and independently pinned hash required")
	}
	var err error
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	switch *controlMode {
	case "run":
		err = runPreparedControl(ctx, *controlRequestPath, *controlRequestSHA)
	case "recover-inspect":
		err = recoverPreparedControl(ctx, *controlRequestPath, *controlRequestSHA, false)
	case "recover-discard":
		err = recoverPreparedControl(ctx, *controlRequestPath, *controlRequestSHA, true)
	default:
		t.Fatal("unknown fixed control mode")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestNativeControlRetainedHives(t *testing.T) {
	plan := os.Getenv("UUP_CONTROL_PLAN")
	if plan == "" {
		t.Skip("retained private hives not configured")
	}
	o, err := inspectControlSource(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err = assertControlBaseline(o); err != nil {
		t.Fatal(err)
	}
	for name, pin := range controlSourceHives {
		if o.Hives[name] != pin.SHA {
			t.Fatalf("%s hash differs", name)
		}
	}
	b, _ := json.Marshal(o)
	t.Log(string(b))
}

func TestNativeControlRetainedToolVersionFields(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(system, "dism.exe")
	file, err := controlComponentReadLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pin, err := controlPinFile(file, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if pin.SHA256 != controlToolSHA {
		t.Skip("fixed private tool profile is not this host's component")
	}
	v, err := controlVersions(path)
	if err != nil {
		t.Fatal(err)
	}
	if v.NumericFileVersion != "10.0.19041.3636" || v.DisplayFileVersion != "10.0.19041.1 (WinBuild.160101.0800)" || v.NumericProductVersion != "10.0.19041.3636" || v.DisplayProductVersion != "10.0.19041.1" {
		t.Fatal(v)
	}
	t.Logf("actual pinned installed tool: links=%d file_id=%+v versions=%+v", pin.Links, pin.Identity, v)
}
