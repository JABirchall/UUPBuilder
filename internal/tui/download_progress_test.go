package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
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
	for _, want := range []string{"packages/source.esd", "apps/source.esd", "50%", "25%", "512 KiB / 1.0 MiB", "256 KiB / 1.0 MiB"} {
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
	for _, want := range []string{"Acquiring helper", "1.5 KiB / unknown", "--%"} {
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
	text := progressText(m, 50, 20)
	for _, want := range []string{"empty.bin", "0 B / 0 B", "Downloading"} {
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
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "empty", "empty\x1b[2J.bin", "completed", 0, &zero)})
	if text := progressText(m, 50, 20); strings.Contains(text, "empty.bin") || len(m.buildAction.downloads) != 0 {
		t.Fatalf("completed empty transfer remained visible: %s", text)
	}
}

func TestCompletedDownloadIsRemovedFromConcurrentTransfers(t *testing.T) {
	for _, test := range []struct {
		name, complete string
		want           []string
	}{
		{"first", "a", []string{"b.bin", "c.bin"}},
		{"middle", "b", []string{"a.bin", "c.bin"}},
		{"last", "c", []string{"a.bin", "b.bin"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
			defer m.Close()
			m.buildAction.busy, m.buildAction.status = true, "Running"
			total := int64(100)
			for _, entry := range []struct{ id, state string }{{"a", "downloading"}, {"b", "verifying"}, {"c", "retrying"}} {
				m = send(m, buildProgressMsg{event: fileProgressEvent(t, entry.id, entry.id+".bin", entry.state, 100, &total)})
			}
			if len(m.buildAction.downloads) != 3 {
				t.Fatal("full byte count removed an unverified transfer")
			}
			m = send(m, buildProgressMsg{event: fileProgressEvent(t, test.complete, test.complete+".bin", "completed", 100, &total)})
			text := progressText(m, 78, 20)
			if len(m.buildAction.downloads) != 2 || strings.Contains(text, test.complete+".bin") {
				t.Fatalf("completed transfer remained visible: %s", text)
			}
			for i, name := range test.want {
				if m.buildAction.downloads[i].name != name || !strings.Contains(text, name) {
					t.Fatalf("completion displaced another transfer: %s", text)
				}
			}
		})
	}
}

func TestCompletionOnlyEventDoesNotCreateProgressHistory(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	total := int64(100)
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "cache", "cached.bin", "completed", 100, &total)})
	text := progressText(m, 78, 20)
	if len(m.buildAction.downloads) != 0 || len(m.buildAction.logs) != 0 || strings.Contains(text, "cached.bin") || strings.Contains(text, "Downloads:") {
		t.Fatalf("completion-only event added download history: %s", text)
	}
}

func TestFailedAndCancelledDownloadsRemainVisible(t *testing.T) {
	for _, test := range []struct{ state, label string }{{"failed", "Failed"}, {"cancelled", "Cancelled"}} {
		t.Run(test.state, func(t *testing.T) {
			m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
			defer m.Close()
			m.buildAction.busy, m.buildAction.status = true, "Running"
			total := int64(100)
			m = send(m, buildProgressMsg{event: fileProgressEvent(t, "diagnostic", "diagnostic.bin", test.state, 100, &total)})
			text := progressText(m, 78, 20)
			if !strings.Contains(text, "diagnostic.bin") || !strings.Contains(text, test.label) {
				t.Fatalf("diagnostic transfer was hidden: %s", text)
			}
		})
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

func TestActiveDownloadRemainsVisibleAfterManyCompletionEvents(t *testing.T) {
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
	if len(m.buildAction.downloads) != 1 || strings.Contains(text, "Downloads:") {
		t.Fatalf("completed downloads consume history or summary space: %s", text)
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

func TestDownloadProgressAnimatesBetweenByteEvents(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	updates := make(chan tea.Msg, 1)
	updates <- nil // Let the independent build event listener complete.
	m.buildAction.updates = updates
	total := int64(100)
	m, cmd := step(m, buildProgressMsg{event: fileProgressEvent(t, "animated", "animated.bin", "downloading", 50, &total)})
	var frame tea.Msg
	for _, msg := range runCommands(cmd) {
		if _, ok := msg.(progress.FrameMsg); ok {
			frame = msg
		}
	}
	if frame == nil {
		t.Fatal("download did not schedule a Bubbles progress animation")
	}
	before := progressText(m, 78, 20)
	for range 8 {
		m, cmd = step(m, frame)
		if cmd == nil {
			t.Fatal("progress animation stopped before advancing to the received byte count")
		}
		frame = cmd()
	}
	after := progressText(m, 78, 20)
	if before == after || !strings.Contains(after, "50%") || !strings.Contains(after, "50 B / 100 B") {
		t.Fatalf("animation did not advance independently of byte events while preserving counters:\n%s", after)
	}
	barLine := func(text string) string {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "B / 100 B") {
				return strings.Fields(line)[0]
			}
		}
		t.Fatal("download bar is missing")
		return ""
	}
	updates <- nil
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "animated", "animated.bin", "downloading", 75, &total)})
	if next := progressText(m, 78, 20); barLine(after) != barLine(next) || !strings.Contains(next, "75%") {
		t.Fatal("a new byte update reset the spring animation instead of preserving its current position")
	}
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "animated", "animated.bin", "completed", 100, &total)})
	_, cmd = step(m, frame)
	if cmd != nil {
		t.Fatal("a removed download continued scheduling animation frames")
	}
}

func TestConcurrentDownloadAnimationFramesStayWithTheirFile(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	updates := make(chan tea.Msg, 1)
	m.buildAction.updates = updates
	total := int64(100)
	var firstFrame tea.Msg
	for _, id := range []string{"first", "second"} {
		updates <- nil
		var cmd tea.Cmd
		m, cmd = step(m, buildProgressMsg{event: fileProgressEvent(t, id, id+".bin", "downloading", 50, &total)})
		for _, msg := range runCommands(cmd) {
			if _, ok := msg.(progress.FrameMsg); ok && id == "first" {
				firstFrame = msg
			}
		}
	}
	barLines := func() []string {
		var bars []string
		for _, line := range strings.Split(progressText(m, 78, 20), "\n") {
			if strings.Contains(line, "50 B / 100 B") {
				bars = append(bars, line)
			}
		}
		if len(bars) != 2 {
			t.Fatalf("missing concurrent download bars: %v", bars)
		}
		return bars
	}
	before := barLines()
	for range 8 {
		var cmd tea.Cmd
		m, cmd = step(m, firstFrame)
		if cmd == nil {
			t.Fatal("first transfer's animation stopped")
		}
		firstFrame = cmd()
	}
	after := barLines()
	if before[0] == after[0] || before[1] != after[1] {
		t.Fatal("a file's animation frame advanced the wrong concurrent progress bar")
	}
}

func TestUnknownDownloadSpinnerStopsAndRejectsPreviousTransferTicks(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m.buildAction.busy, m.buildAction.status = true, "Running"
	updates := make(chan tea.Msg, 1)
	updates <- nil
	m.buildAction.updates = updates
	m, cmd := step(m, buildProgressMsg{event: fileProgressEvent(t, "unknown", "unknown.bin", "downloading", 512, nil)})
	var tick tea.Msg
	for _, msg := range runCommands(cmd) {
		if _, ok := msg.(spinner.TickMsg); ok {
			tick = msg
		}
	}
	if tick == nil {
		t.Fatal("unknown-length download did not start a Bubbles spinner")
	}
	before := progressText(m, 78, 20)
	m, cmd = step(m, tick)
	if cmd == nil || before == progressText(m, 78, 20) {
		t.Fatal("spinner did not animate while no byte event arrived")
	}
	staleTick := cmd()
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "unknown", "unknown.bin", "completed", 512, nil)})
	_, cmd = step(m, staleTick)
	if cmd != nil {
		t.Fatal("spinner kept ticking after the last active download completed")
	}
	updates <- nil
	m = send(m, buildProgressMsg{event: fileProgressEvent(t, "next", "next.bin", "checking", 0, nil)})
	before = progressText(m, 78, 20)
	m, cmd = step(m, staleTick)
	if cmd != nil || before != progressText(m, 78, 20) {
		t.Fatal("a previous download's spinner tick affected a new transfer")
	}
}

func TestUnknownFailedDownloadStaysStillWhileAnotherFileAnimates(t *testing.T) {
	for _, state := range []string{"failed", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
			defer m.Close()
			m.buildAction.busy, m.buildAction.status = true, "Running"
			updates := make(chan tea.Msg, 1)
			updates <- nil
			m.buildAction.updates = updates
			m, cmd := step(m, buildProgressMsg{event: fileProgressEvent(t, "active", "active.bin", "downloading", 512, nil)})
			var tick tea.Msg
			for _, msg := range runCommands(cmd) {
				if _, ok := msg.(spinner.TickMsg); ok {
					tick = msg
				}
			}
			m = send(m, buildProgressMsg{event: fileProgressEvent(t, "diagnostic", "diagnostic.bin", state, 512, nil)})
			diagnosticRows := func() string {
				rows := m.progressRows(78, 20)
				for i, r := range rows {
					if strings.Contains(ansi.Strip(r.text), "diagnostic.bin") && i+1 < len(rows) {
						return r.text + rows[i+1].text
					}
				}
				t.Fatal("diagnostic download is missing")
				return ""
			}
			before := diagnosticRows()
			m, cmd = step(m, tick)
			if cmd == nil || before != diagnosticRows() {
				t.Fatal("a shared spinner frame animated a failed or cancelled unknown-length download")
			}
		})
	}
}
