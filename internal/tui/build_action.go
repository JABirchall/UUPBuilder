package tui

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

type BuildDraft struct {
	Config     config.Config
	ConfigPath string
	Revision   uint64
}
type BuildResult struct {
	JobID     string
	State     string
	Error     string
	Artifacts []model.Artifact
}
type BuildService interface {
	Prepare(context.Context, BuildDraft) (planner.ReadyPlan, error)
	Execute(context.Context, planner.ReadyPlan) (BuildResult, error)
}

// Tool checks must be read-only: no acquisition, source resolution or helpers.
type BuildToolChecker interface {
	CheckTools(context.Context, BuildDraft) ([]string, error)
}
type EventBuildService interface {
	PrepareWithEvents(context.Context, BuildDraft, model.Emit) (planner.ReadyPlan, error)
	ExecuteWithEvents(context.Context, planner.ReadyPlan, model.Emit) (BuildResult, error)
}

type BuildMsg struct{}
type StartBuildMsg struct{}
type CancelBuildMsg struct{}
type buildToolsCheckedMsg struct {
	generation, revision uint64
	tools                []string
	err                  error
}
type buildProgressMsg struct {
	generation uint64
	event      model.Event
}
type buildFinishedMsg struct {
	generation uint64
	plan       planner.ReadyPlan
	result     BuildResult
	err        error
}
type buildActionState struct {
	busy, planning, cancelled, reviewed bool
	generation                          uint64
	cancel                              context.CancelFunc
	draft                               BuildDraft
	tools                               []string
	updates                             <-chan tea.Msg
	logs                                []string
	downloads                           []downloadProgress
	downloadSpinner                     spinner.Model
	downloadSpinning                    bool
	stage, status                       string
	offset, reviewOffset                int
}

func (m Model) beginBuild() (tea.Model, tea.Cmd) {
	if m.buildAction.busy {
		return m.cancelBuild()
	}
	if !m.imageReady() {
		m.notice = "Build blocked: validate image choices in Builds and Image first."
		return m, nil
	}
	cfg, issues := m.conversion.Apply(m.cfg)
	if len(issues) > 0 {
		m.notice = "Build blocked: " + issues[0].Message
		return m, nil
	}
	resolved, err := config.ResolvePaths(cfg, m.configActions.path)
	if err != nil {
		m.notice = "Build blocked: " + err.Error()
		return m, nil
	}
	checker, ok := m.deps.Builder.(BuildToolChecker)
	if !ok {
		m.notice = "Build blocked: tool availability checker unavailable."
		return m, nil
	}
	m.buildAction.generation++
	m.buildAction.busy, m.buildAction.planning = true, true
	m.buildAction.cancelled, m.buildAction.reviewed = false, false
	m.buildAction.reviewOffset = 0
	ctx, cancel := context.WithCancel(m.ctx)
	m.buildAction.cancel = cancel
	draft := BuildDraft{Config: cloneConfig(resolved), ConfigPath: m.configActions.path, Revision: m.revision}
	m.buildAction.draft = draft
	generation := m.buildAction.generation
	m.notice = "Checking required tool availability..."
	return m, func() tea.Msg {
		tools, err := checker.CheckTools(ctx, draft)
		return buildToolsCheckedMsg{generation: generation, revision: draft.Revision, tools: tools, err: err}
	}
}

func (m Model) acceptBuildTools(msg buildToolsCheckedMsg) (tea.Model, tea.Cmd) {
	if !m.buildAction.busy || !m.buildAction.planning || msg.generation != m.buildAction.generation {
		return m, nil
	}
	m.buildAction.cancel()
	m.buildAction.busy, m.buildAction.planning = false, false
	switch {
	case m.buildAction.cancelled:
		m.notice = "Build cancelled before review."
	case msg.revision != m.revision:
		m.notice = "Build discarded: draft changed during tool checks."
	case msg.err != nil:
		m.notice = "Build blocked: " + msg.err.Error()
	default:
		m.buildAction.tools = append([]string(nil), msg.tools...)
		m.buildAction.reviewed = true
		m.notice = "Review the requested settings, then select Start build."
		m.navigate(Review)
	}
	return m, nil
}

func (m Model) startReviewedBuild() (tea.Model, tea.Cmd) {
	if m.buildAction.busy {
		return m, nil
	}
	if !m.buildAction.reviewed {
		m.notice = "Select Build ISO in Conversion to check tools first."
		return m, nil
	}
	cfg, issues := m.conversion.Apply(m.cfg)
	resolved, err := config.ResolvePaths(cfg, m.configActions.path)
	draft := m.buildAction.draft
	if len(issues) > 0 || err != nil || draft.Revision != m.revision || draft.ConfigPath != m.configActions.path || !reflect.DeepEqual(resolved, draft.Config) {
		m.buildAction.reviewed = false
		m.notice = "Build discarded: draft changed after review. Select Build ISO again."
		return m, nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.buildAction.cancel = cancel
	m.buildAction.busy, m.buildAction.cancelled, m.buildAction.reviewed = true, false, false
	m.buildAction.logs, m.buildAction.offset = nil, 0
	m.buildAction.downloads = nil
	m.buildAction.downloadSpinning = false
	m.buildAction.stage, m.buildAction.status = "prepare-source", "Running"
	updates := make(chan tea.Msg, 128)
	m.buildAction.updates = updates
	generation, service, parent := m.buildAction.generation, m.deps.Builder, m.ctx
	m.navigate(Progress)
	m.notice = "Build started. Preparation and build output appear in Progress."
	return m, func() tea.Msg {
		go func() {
			defer close(updates)
			emit := func(event model.Event) {
				select {
				case updates <- buildProgressMsg{generation, event}:
				case <-ctx.Done():
				}
			}
			result := runReviewedBuild(ctx, service, draft, emit)
			result.generation = generation
			select {
			case updates <- result:
			case <-parent.Done():
			}
		}()
		return waitBuildUpdate(parent, updates)()
	}
}

func runReviewedBuild(ctx context.Context, service BuildService, draft BuildDraft, emit model.Emit) (done buildFinishedMsg) {
	emit(model.Event{StageID: "prepare-source", Kind: model.EventStage, Message: "Preparing selected source and required tools"})
	streamed, hasEvents := service.(EventBuildService)
	if hasEvents {
		done.plan, done.err = streamed.PrepareWithEvents(ctx, draft, emit)
	} else {
		done.plan, done.err = service.Prepare(ctx, draft)
	}
	if done.err != nil {
		return
	}
	selection, settings, err := draft.Config.Request()
	if err != nil || done.plan.Validate() != nil || done.plan.Intent() != planner.BuildMedia || done.plan.DraftRevision() != draft.Revision || !reflect.DeepEqual(done.plan.Selection(), selection) || !reflect.DeepEqual(done.plan.RequestedSettings(), settings) {
		done.err = fmt.Errorf("frozen plan does not match the reviewed draft identity")
		return
	}
	if done.err = ctx.Err(); done.err != nil {
		return
	}
	emit(model.Event{StageID: "build", Kind: model.EventStage, Message: "Executing validated build"})
	if hasEvents {
		done.result, done.err = streamed.ExecuteWithEvents(ctx, done.plan, emit)
	} else {
		done.result, done.err = service.Execute(ctx, done.plan)
	}
	return
}
func waitBuildUpdate(ctx context.Context, updates <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-updates:
			return msg
		case <-ctx.Done():
			return nil
		}
	}
}
func (m Model) acceptBuildProgress(msg buildProgressMsg) (tea.Model, tea.Cmd) {
	if !m.buildAction.busy || msg.generation != m.buildAction.generation {
		return m, nil
	}
	if msg.event.StageID != "" {
		m.buildAction.stage = boundedText(msg.event.StageID, 120)
	}
	if m.buildAction.acceptDownload(msg.event) {
		return m, tea.Batch(waitBuildUpdate(m.ctx, m.buildAction.updates), m.buildAction.animateDownloads())
	}
	text := msg.event.Message
	if text == "" && msg.event.CompletedBytes != nil {
		text = fmt.Sprintf("%d bytes", *msg.event.CompletedBytes)
		if msg.event.TotalBytes != nil {
			text += fmt.Sprintf(" / %d", *msg.event.TotalBytes)
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", "\n"), "\n") {
		if line = boundedText(line, 4096); line != "" {
			m.buildAction.logs = append(m.buildAction.logs, line)
			if m.buildAction.offset > 0 {
				m.buildAction.offset++
			}
		}
	}
	if len(m.buildAction.logs) > 1000 {
		m.buildAction.logs = append([]string(nil), m.buildAction.logs[len(m.buildAction.logs)-1000:]...)
	}
	m.buildAction.offset = min(m.buildAction.offset, max(0, len(m.buildAction.logs)-1))
	return m, waitBuildUpdate(m.ctx, m.buildAction.updates)
}
func (m Model) cancelBuild() (tea.Model, tea.Cmd) {
	if m.buildAction.busy {
		m.buildAction.cancelled = true
		m.buildAction.cancel()
		m.buildAction.status = "Cancelling"
		m.notice = "Cancellation requested; waiting for active work and cleanup."
	}
	return m, nil
}
func (m Model) acceptBuildResult(msg buildFinishedMsg) (tea.Model, tea.Cmd) {
	if !m.buildAction.busy || msg.generation != m.buildAction.generation {
		return m, nil
	}
	m.buildAction.cancel()
	m.buildAction.busy, m.buildAction.planning = false, false
	m.buildAction.status = "Finished"
	if msg.err != nil {
		m.buildAction.status = "Failed"
		if msg.result.State == "cancelled" || msg.err == context.Canceled {
			m.buildAction.status = "Cancelled"
		}
		m.notice = "Build " + strings.ToLower(m.buildAction.status) + ": " + msg.err.Error()
	} else {
		m.buildAction.status = msg.result.State
		m.notice = fmt.Sprintf("Build %s: %s", msg.result.JobID, msg.result.State)
		if msg.result.Error != "" {
			m.notice += "; " + msg.result.Error
		}
		for _, artifact := range msg.result.Artifacts {
			m.notice += "; " + artifact.Path
		}
		if msg.plan.Validate() == nil && m.revision == msg.plan.DraftRevision() {
			if customization := msg.plan.CustomizationPlan(); customization != nil && !customization.Apps.Deferred {
				validated := msg.plan
				m.apps.validated = &validated
				m.appsUnchecked = false
			}
		}
	}
	settled := downloadStopped
	if m.buildAction.status == "Failed" || msg.result.State == "failed" {
		settled = model.DownloadFailed
	} else if m.buildAction.status == "Cancelled" || msg.result.State == "cancelled" {
		settled = model.DownloadCancelled
	}
	m.buildAction.settleDownloads(settled)
	m.buildAction.logs = append(m.buildAction.logs, boundedText(m.notice, 4096))
	return m, nil
}
