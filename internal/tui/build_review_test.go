package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

type reviewBuild struct {
	plan                       planner.ReadyPlan
	checks, prepares, executes atomic.Int32
	emit                       model.Emit
	blocked                    chan struct{}
}

func (b *reviewBuild) CheckTools(context.Context, BuildDraft) ([]string, error) {
	b.checks.Add(1)
	return []string{"wimlib: download after Start", "PowerShell: available"}, nil
}
func (b *reviewBuild) Prepare(context.Context, BuildDraft) (planner.ReadyPlan, error) {
	b.prepares.Add(1)
	return b.plan, nil
}
func (b *reviewBuild) Execute(context.Context, planner.ReadyPlan) (BuildResult, error) {
	b.executes.Add(1)
	return BuildResult{JobID: "reviewed-job", State: "succeeded"}, nil
}
func (b *reviewBuild) PrepareWithEvents(ctx context.Context, draft BuildDraft, emit model.Emit) (planner.ReadyPlan, error) {
	emit(model.Event{StageID: "download", Kind: model.EventLog, Message: "Downloading source package"})
	if b.blocked != nil {
		select {
		case <-b.blocked:
		case <-ctx.Done():
			return planner.ReadyPlan{}, ctx.Err()
		}
	}
	return b.Prepare(ctx, draft)
}
func (b *reviewBuild) ExecuteWithEvents(ctx context.Context, plan planner.ReadyPlan, emit model.Emit) (BuildResult, error) {
	emit(model.Event{StageID: "service-image", Kind: model.EventLog, Message: "DISM servicing output"})
	return b.Execute(ctx, plan)
}

func reviewedModel(t *testing.T) (Model, *reviewBuild) {
	m, _ := preparedModel(t, planner.BuildMedia)
	b := &reviewBuild{plan: m.deps.Builder.(preparedBuild).plan}
	m.deps.Builder = b
	return m, b
}

func TestBuildISOChecksToolsThenWaitsInReview(t *testing.T) {
	m, b := reviewedModel(t)
	m, cmd := step(m, BuildMsg{})
	if cmd == nil {
		t.Fatal("tool check not scheduled")
	}
	m, cmd = step(m, cmd())
	if cmd != nil || m.area != Review || b.checks.Load() != 1 || b.prepares.Load() != 0 || b.executes.Load() != 0 {
		t.Fatalf("Build ISO performed work before review: area=%s checks=%d prepares=%d executes=%d", m.area, b.checks.Load(), b.prepares.Load(), b.executes.Load())
	}
	view, _ := m.layout()
	for _, text := range []string{"Start build", "download after Start", "professional"} {
		if !strings.Contains(strings.ToLower(view), strings.ToLower(text)) {
			t.Fatalf("review missing %q: %s", text, view)
		}
	}
	m, _ = step(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if b.prepares.Load() != 0 || b.executes.Load() != 0 {
		t.Fatal("leaving review started work")
	}
}

func drainBuild(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	for i := 0; cmd != nil && i < 100; i++ {
		result := make(chan tea.Msg, 1)
		go func() { result <- cmd() }()
		select {
		case msg := <-result:
			m, cmd = step(m, msg)
		case <-time.After(3 * time.Second):
			t.Fatal("build event stream did not finish")
		}
	}
	if m.buildAction.busy {
		t.Fatal("build remained busy after completion")
	}
	return m
}

func TestReviewStartStreamsPreparationAndExecutionInProgress(t *testing.T) {
	m, b := reviewedModel(t)
	m, check := step(m, BuildMsg{})
	m, _ = step(m, check())
	m, cmd := step(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || m.area != Progress {
		t.Fatal("Start did not open Progress")
	}
	m = drainBuild(t, m, cmd)
	if b.prepares.Load() != 1 || b.executes.Load() != 1 {
		t.Fatalf("wrong execution count: %d %d", b.prepares.Load(), b.executes.Load())
	}
	view, _ := m.layout()
	for _, text := range []string{"Downloading source package", "DISM servicing output", "reviewed-job"} {
		if !strings.Contains(view, text) {
			t.Fatalf("progress missing %q: %s", text, view)
		}
	}
}

func TestReviewRejectsChangedDraftWithoutPreparing(t *testing.T) {
	m, b := reviewedModel(t)
	m, check := step(m, BuildMsg{})
	m, _ = step(m, check())
	m = send(m, ConversionFieldChangedMsg{Key: "conversion.cleanup", Value: strconv.FormatBool(!m.cfg.Conversion.Cleanup)})
	m, cmd := step(m, StartBuildMsg{})
	if cmd != nil || b.prepares.Load() != 0 || !strings.Contains(m.notice, "draft changed") {
		t.Fatalf("stale review started: %s", m.notice)
	}
}

func TestProgressCancellationDuringPreparationNeverExecutes(t *testing.T) {
	m, b := reviewedModel(t)
	b.blocked = make(chan struct{})
	m, check := step(m, BuildMsg{})
	m, _ = step(m, check())
	m, cmd := step(m, StartBuildMsg{})
	m, next := step(m, cmd())
	m, _ = step(m, CancelBuildMsg{})
	m = drainBuild(t, m, next)
	if b.executes.Load() != 0 || !strings.Contains(m.notice, "cancelled") {
		t.Fatalf("cancel did not stop preparation: %s", m.notice)
	}
}

func TestProgressLogsAreSanitizedBoundedAndScrollable(t *testing.T) {
	m, _ := reviewedModel(t)
	m.buildAction.busy = true
	m.buildAction.generation = 7
	m.buildAction.status = "Running"
	m.area = Progress
	for i := 0; i < 1010; i++ {
		m, _ = step(m, buildProgressMsg{generation: 7, event: model.Event{Kind: model.EventLog, Message: "line\x1b[2J\nsecond"}})
	}
	if len(m.buildAction.logs) != 1000 || strings.Contains(strings.Join(m.buildAction.logs, ""), "\x1b") {
		t.Fatal("logs are unbounded or contain terminal controls")
	}
	m.move(-10)
	if m.buildAction.offset != 10 {
		t.Fatal("progress does not scroll")
	}
	m, _ = step(m, tea.KeyPressMsg{Code: tea.KeyEnd})
	if m.buildAction.offset != 0 {
		t.Fatal("End does not follow latest logs")
	}
}

func TestReviewToolsRemainReachableInCompactLayout(t *testing.T) {
	m, _ := reviewedModel(t)
	m, check := step(m, BuildMsg{})
	m, _ = step(m, check())
	m.width, m.height = 64, 20
	m.buildAction.tools = []string{"extractor: available", "PowerShell: available", "ISO library: available", "wimlib: download after Start", "DISM: download after Start"}
	m.move(1000)
	view, _ := m.layout()
	if !strings.Contains(view, "DISM: download after Start") { t.Fatalf("compact Review hides tools: %s", view) }
}

func TestCancellationDoesNotHideCleanupFailure(t *testing.T) {
	m, _ := reviewedModel(t)
	_, cancel := context.WithCancel(context.Background())
	m.buildAction.cancel = cancel
	m.buildAction.busy, m.buildAction.cancelled = true, true
	m = send(m, buildFinishedMsg{err: errors.Join(context.Canceled, fmt.Errorf("workspace resources preserved: cleanup failed"))})
	if m.buildAction.status != "Failed" || !strings.Contains(m.notice, "preserved") { t.Fatalf("cleanup failure hidden as cancellation: %s", m.notice) }
}
