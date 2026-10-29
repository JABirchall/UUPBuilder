package tui

import (
	"context"
	"fmt"
	"reflect"

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
type BuildMsg struct{}
type buildPreparedMsg struct {
	generation, revision uint64
	plan                 planner.ReadyPlan
	err                  error
}
type buildFinishedMsg struct {
	generation uint64
	result     BuildResult
	err        error
}
type buildActionState struct {
	busy       bool
	planning   bool
	cancelled  bool
	generation uint64
	cancel     context.CancelFunc
	draft      BuildDraft
}

func (m Model) beginBuild() (tea.Model, tea.Cmd) {
	if m.buildAction.busy {
		m.buildAction.cancelled = true
		if m.buildAction.cancel != nil {
			m.buildAction.cancel()
		}
		m.notice = "Cancellation requested for the active build action."
		return m, nil
	}
	if !m.image.ready(m.cfg.Image) {
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
	if m.deps.Builder == nil {
		m.notice = "Build blocked: planning/controller producer unavailable."
		return m, nil
	}
	m.buildAction.generation++
	m.buildAction.busy = true
	m.buildAction.planning = true
	m.buildAction.cancelled = false
	ctx, cancel := context.WithCancel(m.ctx)
	m.buildAction.cancel = cancel
	draft := BuildDraft{Config: resolved, ConfigPath: m.configActions.path, Revision: m.revision}
	m.buildAction.draft = draft
	generation, service := m.buildAction.generation, m.deps.Builder
	m.notice = "Checking source, requested settings, storage and execution providers..."
	return m, func() tea.Msg {
		plan, err := service.Prepare(ctx, draft)
		return buildPreparedMsg{generation: generation, revision: draft.Revision, plan: plan, err: err}
	}
}
func (m Model) acceptBuildPlan(msg buildPreparedMsg) (tea.Model, tea.Cmd) {
	if !m.buildAction.busy || !m.buildAction.planning || msg.generation != m.buildAction.generation {
		return m, nil
	}
	fail := func(message string) (tea.Model, tea.Cmd) {
		m.buildAction.cancel()
		m.buildAction.busy = false
		m.buildAction.planning = false
		m.notice = message
		return m, nil
	}
	if m.buildAction.cancelled {
		return fail("Build cancelled before execution.")
	}
	if msg.revision != m.revision {
		return fail("Build discarded: draft changed during preflight.")
	}
	if msg.err != nil {
		return fail("Build blocked: " + msg.err.Error())
	}
	selection, settings, err := m.buildAction.draft.Config.Request()
	if err != nil || msg.plan.Validate() != nil || msg.plan.Intent() != planner.BuildMedia || msg.plan.DraftRevision() != m.revision || !reflect.DeepEqual(msg.plan.Selection(), selection) || !reflect.DeepEqual(msg.plan.RequestedSettings(), settings) {
		return fail("Build blocked: frozen plan does not match the current draft identity.")
	}
	m.buildAction.planning = false
	ctx, cancel := context.WithCancel(m.ctx)
	m.buildAction.cancel()
	m.buildAction.cancel = cancel
	generation, service, plan := m.buildAction.generation, m.deps.Builder, msg.plan
	m.notice = "Executing the validated build request. Draft edits apply to the next build."
	return m, func() tea.Msg {
		result, err := service.Execute(ctx, plan)
		return buildFinishedMsg{generation: generation, result: result, err: err}
	}
}
func (m Model) acceptBuildResult(msg buildFinishedMsg) (tea.Model, tea.Cmd) {
	if !m.buildAction.busy || msg.generation != m.buildAction.generation {
		return m, nil
	}
	m.buildAction.cancel()
	m.buildAction.busy = false
	if msg.err != nil {
		m.notice = "Build failed: " + msg.err.Error()
		return m, nil
	}
	m.notice = fmt.Sprintf("Build %s: %s", msg.result.JobID, msg.result.State)
	if msg.result.Error != "" {
		m.notice += "; " + msg.result.Error
	}
	for _, artifact := range msg.result.Artifacts {
		m.notice += "; " + artifact.Path
	}
	return m, nil
}
