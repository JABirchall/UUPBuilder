package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

// JSON exercises the optional event contract while preserving older emitters.
func fileProgressEvent(t *testing.T, id, name, state string, completed int64, total *int64) model.Event {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"stage_id": "downloads", "kind": "bytes", "message": "Downloading payload",
		"completed_bytes": completed, "total_bytes": total,
		"download": map[string]string{"id": id, "name": name, "state": state},
	})
	if err != nil {
		t.Fatal(err)
	}
	var event model.Event
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	return event
}

func progressText(m Model, width, height int) string {
	var lines []string
	for _, r := range m.progressRows(width, height) {
		lines = append(lines, ansi.Strip(r.text))
	}
	return strings.Join(lines, "\n")
}

func TestDownloadBarsUpdateInPlaceWithConcurrentFileIdentity(t *testing.T) {
	// Losing counters when Message is present, or appending every chunk to logs,
	// would hide the actual progress and evict useful build output.
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	total := int64(1 << 20)
	for i := int64(0); i <= 512; i++ {
		m = send(m, buildProgressMsg{event: fileProgressEvent(t, "a", "packages/source.esd", "downloading", i*1024, &total)})
	}
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "b", "apps/source.esd", "downloading", 256*1024, &total)})
	text := progressText(m, 78, 20)
	for _, want := range []string{"packages/source.esd", "apps/source.esd", "50%", "25%", "512 KiB / 1.0 MiB", "256 KiB / 1.0 MiB", "[", "#", "-", "]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in progress:\n%s", want, text)
		}
	}
	if strings.Count(text, "packages/source.esd") != 1 || len(m.buildAction.logs) != 0 {
		t.Fatalf("byte updates became history: rows=%s logs=%d", text, len(m.buildAction.logs))
	}
}

func TestGenericByteEventsRetainCountersAndUnknownTotals(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	n := int64(1536)
	m = send(m, buildProgressMsg{event: model.Event{StageID: "tools", Kind: model.EventBytes, Message: "Acquiring helper", CompletedBytes: &n}})
	text := progressText(m, 78, 15)
	for _, want := range []string{"Acquiring helper", "1.5 KiB / unknown", "--%", "["} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
}

func TestDownloadBarsHandleZeroTotalsAndFitNarrowTerminals(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	zero := int64(0)
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "empty", "empty\x1b[2J.bin", "downloading", 0, &zero)})
	if text := progressText(m, 50, 20); !strings.Contains(text, "--%") || strings.Contains(text, "100%") {
		t.Fatalf("unverified zero-length transfer claims completion: %s", text)
	}
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "empty", "empty\x1b[2J.bin", "completed", 0, &zero)})
	text := progressText(m, 50, 20)
	for _, want := range []string{"100%", "0 B / 0 B", "Completed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
	for _, width := range []int{1, 8, 24, 36, 50} {
		for _, r := range m.progressRows(width, 20) {
			if strings.Contains(ansi.Strip(r.text), "\x1b") || ansi.StringWidth(r.text) > width {
				t.Fatalf("unsafe/oversized row at width %d: %q", width, r.text)
			}
		}
	}
}

func TestBuildCompletionSettlesActiveBarsAndNewBuildResetsThem(t *testing.T) {
	for _, result := range []struct {
		name        string
		err         error
		state, want string
	}{
		{"failure", fmt.Errorf("bad digest"), "", "Failed"},
		{"cancel", context.Canceled, "cancelled", "Cancelled"},
		{"finished", nil, "succeeded", "Stopped"},
	} {
		t.Run(result.name, func(t *testing.T) {
			m, _ := reviewedModel(t)
			m, check := step(m, BuildMsg{})
			m, _ = step(m, check())
			m, _ = step(m, StartBuildMsg{})
			total := int64(100)
			m = send(m, buildProgressMsg{generation: m.buildAction.generation, event: fileProgressEvent(t, "old", "old.bin", "downloading", 50, &total)})
			m = send(m, buildFinishedMsg{generation: m.buildAction.generation, result: BuildResult{State: result.state}, err: result.err})
			if text := progressText(m, 78, 20); !strings.Contains(text, result.want) || strings.Contains(text, "100%") {
				t.Fatalf("unfinished transfer incorrectly settled: %s", text)
			}
			m, check = step(m, BuildMsg{})
			m, _ = step(m, check())
			m, _ = step(m, StartBuildMsg{})
			if text := progressText(m, 78, 20); strings.Contains(text, "old.bin") {
				t.Fatalf("new build kept old bars: %s", text)
			}
			m.Close()
		})
	}
}

func TestActiveDownloadRemainsVisibleAfterLargeCompletedHistory(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	total := int64(100)
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "active", "active.bin", "downloading", 25, &total)})
	for i := range 300 {
		m = send(m, buildProgressMsg{event: fileProgressEvent(t, fmt.Sprint(i), fmt.Sprintf("completed-%d.bin", i), "completed", 100, &total)})
	}
	text := progressText(m, 78, 9)
	if !strings.Contains(text, "active.bin") || !strings.Contains(text, "25%") {
		t.Fatalf("completed history hid active file: %s", text)
	}
	if len(m.buildAction.downloads) > 128 {
		t.Fatalf("unbounded progress history: %d entries", len(m.buildAction.downloads))
	}
}

func TestDownloadStatusSurvivesLongFilenameClipping(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	total := int64(100)
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "long", strings.Repeat("payload-", 40)+".esd", "failed", 100, &total)})
	if text := progressText(m, 36, 12); !strings.Contains(text, "Failed") {
		t.Fatalf("long filename hid failure state: %s", text)
	}
}

func TestCompletedCacheHistoryCannotDisplaceActiveTransfersAtCapacity(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	total := int64(100)
	for i := range 128 {
		m = send(m, buildProgressMsg{event: fileProgressEvent(t, fmt.Sprint(i), fmt.Sprintf("active-%d.bin", i), "downloading", 25, &total)})
	}
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "cache-hit", "cached.bin", "completed", 100, &total)})
	text := progressText(m, 78, 12)
	if !strings.Contains(text, "active-0.bin") || strings.Contains(text, "127 active") {
		t.Fatalf("cache history displaced an active file: %s", text)
	}
}

func TestIdleProgressRowsRespectAvailableCells(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	for _, height := range []int{0, 1, 4} {
		rows := m.progressRows(8, height)
		if len(rows) > height {
			t.Fatalf("idle progress exceeded height %d: %d", height, len(rows))
		}
		for _, row := range rows {
			if ansi.StringWidth(row.text) > 8 {
				t.Fatalf("idle progress exceeded width: %q", row.text)
			}
		}
	}
}
