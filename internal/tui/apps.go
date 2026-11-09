package tui

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	"uupbuilder/internal/source"
)

type appsState struct {
	validated     *planner.ReadyPlan
	generation    uint64
	selection     model.Selection
	endpoint      string
	cancel        context.CancelFunc
	status        requestStatus
	loadFrame     int
	snapshot      source.AppCatalogSnapshot
	search        textinput.Model
	focus, cursor int // mode, stub preference, family list, All offered preset
}

func (m Model) validatedApps() bool {
	if m.apps.validated == nil {
		return false
	}
	p := *m.apps.validated
	c := p.CustomizationPlan()
	return c != nil && !c.Apps.Deferred && p.DraftRevision() == m.revision && sameAppSelection(p.Selection(), m.cfg.Image) && reflect.DeepEqual(c.Apps.Requested, m.cfg.Apps) && c.Source == p.Manifest().Source
}

type appsResultMsg struct {
	generation uint64
	selection  model.Selection
	endpoint   string
	snapshot   source.AppCatalogSnapshot
	err        error
	checkedAt  time.Time
}
type appsLoadTickMsg struct{ generation uint64 }
type appModeMsg struct{ mode model.AppMode }
type appStubMsg struct{ policy model.AppStubPolicy }
type appToggleMsg struct{ featureID string }
type appSearchMsg struct{}
type appControlMsg struct{ field int }

func newAppsState() appsState {
	input := newBuildsState().filter
	input.Placeholder = "source app families"
	return appsState{search: input, focus: 2}
}
func sameAppSelection(a, b model.Selection) bool {
	return a.UpdateID == b.UpdateID && a.Architecture == b.Architecture && a.Language == b.Language && slices.Equal(a.Editions, b.Editions)
}
func (m *Model) invalidateApps() {
	if m.apps.cancel != nil {
		m.apps.cancel()
	}
	m.apps.generation++
	m.apps.cancel = nil
	m.apps.selection = model.Selection{}
	m.apps.snapshot = source.AppCatalogSnapshot{}
	m.apps.validated = nil
	m.apps.status = requestStatus{}
	m.apps.loadFrame = 0
	m.apps.cursor = 0
	m.appsUnchecked = true
}
func (m *Model) beginApps(force bool) tea.Cmd {
	if !m.imageReady() {
		return nil
	}
	if !force && sameAppSelection(m.apps.selection, m.cfg.Image) && m.apps.endpoint == m.cfg.Catalog.Endpoint && (m.apps.status.loading || !m.apps.status.checkedAt.IsZero()) {
		return nil
	}
	m.invalidateApps()
	m.apps.selection = m.cfg.Image
	m.apps.selection.Editions = slices.Clone(m.cfg.Image.Editions)
	m.apps.endpoint = m.cfg.Catalog.Endpoint
	if m.deps.AppCatalog == nil {
		m.apps.status = resultStatus(errors.New("source app catalogue unavailable in this workspace"), time.Now())
		return nil
	}
	// A source may need many metadata lookups and a queued online request.
	// Bound individual HTTP attempts in the producer, not the whole load.
	ctx, cancel := context.WithCancel(m.ctx)
	if force {
		ctx = catalog.WithRefresh(ctx)
	}
	m.apps.cancel = cancel
	m.apps.status = requestStatus{loading: true}
	generation, selection, endpoint, loader := m.apps.generation, m.apps.selection, m.apps.endpoint, m.deps.AppCatalog
	selection.Editions = slices.Clone(selection.Editions)
	load := func() tea.Msg {
		defer cancel()
		portSelection := selection
		portSelection.Editions = slices.Clone(selection.Editions)
		snapshot, err := loader.Load(ctx, portSelection)
		return appsResultMsg{generation: generation, selection: selection, endpoint: endpoint, snapshot: snapshot.Clone(), err: err, checkedAt: time.Now()}
	}
	return tea.Batch(load, appsLoadTick(generation))
}

func appsLoadTick(generation uint64) tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return appsLoadTickMsg{generation} })
}

func (m *Model) acceptApps(msg appsResultMsg) {
	// App request edits do not change this source observation's identity. Guard
	// source generation + exact tuple/endpoint, rather than the whole draft, so
	// pending metadata can never apply to a superseded source.
	if msg.generation != m.apps.generation || msg.endpoint != m.cfg.Catalog.Endpoint || !sameAppSelection(msg.selection, m.cfg.Image) || !sameAppSelection(msg.selection, m.apps.selection) {
		return
	}
	m.apps.status = resultStatus(msg.err, msg.checkedAt)
	m.apps.cancel = nil
	if msg.err != nil {
		return
	}
	if !sameAppSelection(msg.snapshot.Selection, msg.selection) {
		m.apps.status.err = errors.New("app catalogue selection changed")
		return
	}
	m.apps.snapshot = msg.snapshot.Clone()
	if m.apps.snapshot.State == source.AppCatalogAvailable && len(m.cfg.Apps.Include) > 0 {
		m.reconcileAppSelections()
	}
	m.apps.cursor = min(m.apps.cursor, max(0, len(m.appChoices())-1))
}

func (m *Model) reconcileAppSelections() {
	offered := make(map[string]bool, len(m.apps.snapshot.Entries))
	for _, entry := range m.apps.snapshot.Entries {
		if offeredToSelectedEdition(entry, m.cfg.Image.Editions) {
			offered[entry.FeatureID] = true
		}
	}
	var retained []string
	for _, id := range m.cfg.Apps.Include {
		if offered[id] {
			retained = append(retained, id)
		}
	}
	if len(retained) < len(m.cfg.Apps.Include) {
		m.cfg.Apps.Include = retained
		m.appEdited()
		m.notice = "Removed saved app selections unavailable for the current source."
	}
}

func (m Model) appChoices() []*source.AppCatalogEntry {
	if !m.appOffersExamined() {
		return nil
	}
	var rows []*source.AppCatalogEntry
	known := map[string]bool{}
	query := strings.ToLower(m.apps.search.Value())
	for i := range m.apps.snapshot.Entries {
		entry := &m.apps.snapshot.Entries[i]
		if !offeredToSelectedEdition(*entry, m.cfg.Image.Editions) || known[entry.FeatureID] {
			continue
		}
		known[entry.FeatureID] = true
		if query == "" || strings.Contains(strings.ToLower(entry.FeatureID), query) {
			rows = append(rows, entry)
		}
	}
	return rows
}
func (m *Model) appEdited() {
	m.appsUnchecked = true
	m.revision++
	m.conversion.applicability = nil
	m.notice = "App requests changed; manifest, licensing and provisioning applicability remain pending."
}
func (m *Model) setAppMode(mode model.AppMode) {
	if mode != model.AppsDefault && mode != model.AppsCustom && mode != model.AppsNone {
		return
	}
	if m.cfg.Apps.Mode == mode {
		return
	}
	m.cfg.Apps.Mode = mode
	m.appEdited()
}
func (m *Model) setAppStub(policy model.AppStubPolicy) {
	if policy != model.AppStubAuto && policy != model.AppStub && policy != model.AppFull {
		return
	}
	if m.cfg.Apps.StubPolicy == policy {
		return
	}
	m.cfg.Apps.StubPolicy = policy
	m.appEdited()
}
func (m *Model) toggleApp(id string) {
	allowed := false
	for i, choice := range m.appChoices() {
		if choice.FeatureID == id {
			allowed = true
			m.apps.cursor = i
			break
		}
	}
	if !allowed {
		return
	}
	index := slices.Index(m.cfg.Apps.Include, id)
	if m.cfg.Apps.Mode != model.AppsCustom {
		m.cfg.Apps.Mode = model.AppsCustom
		if index < 0 {
			m.cfg.Apps.Include = append(m.cfg.Apps.Include, id)
		}
	} else if index >= 0 {
		m.cfg.Apps.Include = slices.Delete(m.cfg.Apps.Include, index, index+1)
	} else {
		m.cfg.Apps.Include = append(m.cfg.Apps.Include, id)
	}
	m.apps.focus = 2
	m.cfg.Apps.Preset = ""
	m.apps.cursor = min(m.apps.cursor, max(0, len(m.appChoices())-1))
	m.appEdited()
}
func (m Model) activateAppControl() (tea.Model, tea.Cmd) {
	switch m.apps.focus {
	case 0:
		modes := []model.AppMode{model.AppsDefault, model.AppsCustom, model.AppsNone}
		index := slices.Index(modes, m.cfg.Apps.Mode)
		m.setAppMode(modes[(index+1)%len(modes)])
	case 1:
		policies := []model.AppStubPolicy{model.AppStubAuto, model.AppStub, model.AppFull}
		index := slices.Index(policies, m.cfg.Apps.StubPolicy)
		m.setAppStub(policies[(index+1)%len(policies)])
	case 3:
		m.applyAppPreset(allOfferedPreset)
	default:
		m.navigate(Conversion)
	}
	return m, nil
}
func (m Model) updateAppInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok && (key.String() == "enter" || key.String() == "esc") {
		m.apps.search.Blur()
		m.apps.focus = 2
		return m, nil
	}
	var cmd tea.Cmd
	m.apps.search, cmd = m.apps.search.Update(msg)
	m.apps.cursor = 0
	return m, cmd
}
func (m Model) appsRows(width, height int) []row {
	rows := []row{{text: heading.Render("Choose included apps")}}
	examined := m.appOffersExamined()
	choices := m.appChoices()
	var status string
	switch {
	case m.apps.status.loading:
		status = "Loading app metadata..."
	case !m.imageReady():
		status = "Choose a validated language and edition to examine source app metadata."
	case m.apps.status.err != nil:
		status = "App catalogue unavailable | r retry: " + boundedText(m.apps.status.err.Error(), 160)
	case examined:
		offered := map[string]bool{}
		for _, e := range m.apps.snapshot.Entries {
			if offeredToSelectedEdition(e, m.cfg.Image.Editions) {
				offered[e.FeatureID] = true
			}
		}
		status = fmt.Sprintf("%d source-offered · %d visible · applicability pending", len(offered), len(choices))
	case len(m.apps.snapshot.Gaps) > 0:
		status = "Deferred | " + m.apps.snapshot.Gaps[0]
	default:
		status = "Source app metadata has not been examined; r retry."
	}
	if m.validatedApps() {
		status = "Source manifests, app closure and requested policies validated for this draft."
	}
	statusRows := []row{{text: muted.Render(status)}}
	if m.apps.status.loading {
		barWidth := min(24, width)
		markerWidth := min(4, barWidth)
		offset := m.apps.loadFrame % (barWidth - markerWidth + 1)
		bar := rule(offset) + accent.Render(strings.Repeat("━", markerWidth)) + rule(barWidth-markerWidth-offset)
		statusRows = append(statusRows, row{text: bar})
	}
	if height < 5 && m.apps.search.Focused() {
		search := controlRows("Search (/)", inputView(m.apps.search, max(1, width-16)), width, true, true, appSearchMsg{})
		return append(search, statusRows...)
	}
	if !examined {
		rows = append(rows, statusRows...)
	}
	controls := joinControls(controlRows("Mode (d/c/n)", string(m.cfg.Apps.Mode), max(1, (width-2)/2), m.apps.focus == 0, true, appControlMsg{field: 0}), controlRows("Stub preference", string(m.cfg.Apps.StubPolicy), max(1, width-(width-2)/2-2), m.apps.focus == 1, true, appControlMsg{field: 1}))
	if width < 46 {
		controls = append(controlRows("Mode", string(m.cfg.Apps.Mode), width, m.apps.focus == 0, true, appControlMsg{field: 0}), controlRows("Stub preference", string(m.cfg.Apps.StubPolicy), width, m.apps.focus == 1, true, appControlMsg{field: 1})...)
	}
	rows = append(rows, controls...)
	preset := "apply to current source"
	if !examined {
		preset = "unavailable; metadata unexamined"
	} else if m.cfg.Apps.Preset == allOfferedPreset {
		preset = "saved request; apply again to replace"
	}
	rows = append(rows, controlRows("All offered (a)", preset, width, m.apps.focus == 3, true, appControlMsg{field: 3})...)
	if m.cfg.Apps.Preset != "" && m.cfg.Apps.Preset != allOfferedPreset {
		rows = append(rows, row{text: muted.Render("Preset: unresolved " + terminalText(m.cfg.Apps.Preset))})
	}
	if height >= 7 || m.apps.search.Focused() {
		rows = append(rows, controlRows("Search (/)", inputView(m.apps.search, max(1, width-16)), width, m.apps.search.Focused(), true, appSearchMsg{})...)
	}
	if examined {
		rows = append(rows, statusRows...)
	}
	if height >= 8 {
		semantics := "Default: engine/source defaults; boxes show no explicit custom requests."
		if m.cfg.Apps.Mode == model.AppsCustom {
			semantics = "Custom: checked families are explicit requests; source hints are not policy locks."
		}
		if m.cfg.Apps.Mode == model.AppsNone {
			semantics = "None: request no apps; previous custom families are retained."
		}
		rows = append(rows, row{text: muted.Render(semantics)})
	}
	count := max(1, height-len(rows))
	if height >= 10 {
		count = max(1, count-2)
	}
	start := max(0, m.apps.cursor-count+1)
	for i := start; i < min(len(choices), start+count); i++ {
		choice := choices[i]
		check := "[ ]"
		if m.cfg.Apps.Mode == model.AppsCustom && slices.Contains(m.cfg.Apps.Include, choice.FeatureID) {
			check = "[x]"
		}
		prefix := "  "
		focused := m.apps.focus == 2 && i == m.apps.cursor
		if focused {
			prefix = "> "
		}
		rows = append(rows, row{text: selectedLine(prefix+check+" "+terminalText(choice.FeatureID), width, focused), msg: appToggleMsg{featureID: choice.FeatureID}})
	}
	if len(choices) == 0 && examined {
		rows = append(rows, row{text: muted.Render("No matching source app families.")})
	}
	if height >= 10 && len(choices) > m.apps.cursor {
		e := choices[m.apps.cursor]
		memberships := []string{}
		for _, ref := range e.Editions {
			memberships = append(memberships, ref.Edition+":"+ref.Type)
		}
		detail := strings.Join(memberships, ", ") + fmt.Sprintf(" · %d source dependencies", len(e.Dependencies))
		if len(e.InitialIntents) > 0 {
			detail += " · " + strings.Join(e.InitialIntents, ",")
		}
		for _, license := range e.Licenses {
			if !license.FamilyMatchesIgnoringCase {
				detail = "Unresolved license PFM mismatch: " + license.PFM
			}
		}
		dependencies := "Manifest, package closure, licensing and provisioning checks remain pending."
		if len(e.Dependencies) > 0 {
			names := []string{}
			for _, dep := range e.Dependencies {
				names = append(names, dep.FeatureID+" ("+dep.Type+")")
			}
			dependencies = "Source dependencies: " + strings.Join(names, ", ")
		}
		rows = append(rows, row{text: muted.Render(terminalText(detail))}, row{text: muted.Render(terminalText(dependencies))})
	}
	// Compact views keep the focused control or checkbox reachable. The global
	// summary retains its pending-applicability notice independently.
	if height < 5 && len(rows) > height {
		for i, r := range rows {
			focused := false
			switch msg := r.msg.(type) {
			case appToggleMsg:
				focused = m.apps.focus == 2 && len(choices) > m.apps.cursor && msg.featureID == choices[m.apps.cursor].FeatureID
			case appControlMsg:
				focused = m.apps.focus == msg.field
			}
			if focused {
				return append(statusRows, rows[i:]...)
			}
		}
	}
	return rows
}
