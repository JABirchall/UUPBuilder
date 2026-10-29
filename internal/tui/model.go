// Package tui owns the Workspace draft and discovery interface. It does not
// start conversion tools or own a job lifecycle.
package tui

import (
	"context"
	"slices"

	tea "charm.land/bubbletea/v2"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

// DraftSnapshot is independent of the model and caller's configuration. Config
// retains requested policies; ImageReady means only catalogue choices have
// been checked, never preflight/build readiness. AppsApplicable remains false
// until a later metadata/editor owner validates real app applicability.
// Source.BuildLabel is empty until its exact catalogue record is retrieved;
// this is browsing state, not a frozen manifest/source-validation guarantee.
type DraftSnapshot struct {
	Revision         uint64
	ConfigPath       string
	Config           config.Config
	Source           model.SourceIdentity
	HasCatalogRecord bool
	ImageReady       bool
	AppsApplicable   bool
	Notice           string
	AppsNotice       string
}

type Model struct {
	deps          Dependencies
	cfg           config.Config
	ctx           context.Context
	close         context.CancelFunc
	initialized   bool
	revision      uint64
	source        *catalog.Build
	area          Area
	width, height int
	builds        buildsState
	image         imageState
	apps          appsState
	conversion    ConversionModel
	configActions configActionsState
	notice        string
	showHelp      bool
	showTOML      bool
	tomlOffset    int
	appsUnchecked bool
}

func New(deps Dependencies, cfg config.Config) Model {
	if deps.Context == nil {
		deps.Context = context.Background()
	}
	if deps.Catalog == nil {
		if deps.CatalogFactory == nil {
			deps.CatalogFactory = func(endpoint string) Catalog { return catalog.New(nil, endpoint) }
		}
		deps.Catalog = catalog.New(nil, cfg.Catalog.Endpoint)
	}
	ctx, cancel := context.WithCancel(deps.Context)
	m := Model{deps: deps, cfg: cloneConfig(cfg), ctx: ctx, close: cancel, revision: 1, width: 110, height: 30, builds: newBuildsState(), apps: newAppsState()}
	m.conversion = NewConversionModel(cfg, nil)
	m.configActions.path = deps.ConfigPath
	if m.cfg.Image.UpdateID == "" {
		m.cfg.Image.Language = ""
		m.cfg.Image.Editions = nil
	} else {
		m.appsUnchecked = true
		m.notice = "Loaded image choices need catalogue validation; app applicability is unchecked."
	}
	return m
}

// Close cancels discovery owned by this Workspace. The embedding application
// should defer it as well as cancelling Dependencies.Context on shutdown.
func (m Model) Close()        { m.close() }
func (m Model) Init() tea.Cmd { return func() tea.Msg { return initializeMsg{} } }
func (m Model) Snapshot() DraftSnapshot {
	source := model.SourceIdentity{UpdateID: m.cfg.Image.UpdateID, Architecture: m.cfg.Image.Architecture, Language: m.cfg.Image.Language}
	if m.source != nil {
		source.BuildLabel = m.source.Title
	}
	appsNotice := ""
	if m.appsUnchecked {
		appsNotice = appsUncheckedNotice
	}
	return DraftSnapshot{Revision: m.revision, ConfigPath: m.configActions.path, Config: cloneConfig(m.cfg), Source: source, HasCatalogRecord: m.source != nil, ImageReady: m.image.ready(m.cfg.Image), Notice: m.notice, AppsNotice: appsNotice}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case initializeMsg:
		if m.initialized {
			return m, nil
		}
		m.initialized = true
		search := m.beginSearch(false)
		if m.cfg.Image.UpdateID != "" {
			languages := m.beginLanguages(false)
			return m, tea.Batch(search, languages)
		}
		return m, search
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.builds.search.SetWidth(max(1, m.contentWidth()-14))
		m.builds.filter.SetWidth(max(1, m.contentWidth()-14))
		m.apps.search.SetWidth(max(1, m.contentWidth()-16))
	case NavigateMsg:
		m.navigate(msg.Area)
		if m.area == Apps {
			return m, m.beginApps(false)
		}
	case appsResultMsg:
		m.acceptApps(msg)
	case appModeMsg:
		m.setAppMode(msg.mode)
	case appStubMsg:
		m.setAppStub(msg.policy)
	case appToggleMsg:
		m.toggleApp(msg.featureID)
	case appControlMsg:
		m.apps.focus = msg.field
		return m.activateAppControl()
	case appSearchMsg:
		return m, m.apps.search.Focus()
	case viewTOMLMsg:
		m.showTOML = !m.showTOML
		m.showHelp = false
		m.tomlOffset = 0
	case buildInputMsg:
		m.builds.search.Blur()
		m.builds.filter.Blur()
		if msg.filter {
			cmd := m.builds.filter.Focus()
			return m, cmd
		}
		cmd := m.builds.search.Focus()
		return m, cmd
	case cycleTargetFilterMsg:
		m.builds.search.Blur()
		m.builds.filter.Blur()
		m.cycleFilter()
	case ConversionFieldChangedMsg:
		m.changeConversion(msg.Key, msg.Value)
	case ConfigPathChangedMsg:
		m.changeConfigPath(msg.Path)
	case LoadConfigMsg:
		return m.beginConfigAction(false)
	case SaveConfigMsg:
		return m.beginConfigAction(true)
	case configActionResultMsg:
		return m.acceptConfigAction(msg)
	case conversionFocusMsg:
		m.conversion.cursor = max(0, min(msg.index, configControlCount+len(m.conversion.fields)-1))
		m.conversion.input.Blur()
		return m.activate()
	case SearchChangedMsg:
		return m.changeQuery(msg.Query)
	case searchDebouncedMsg:
		if msg.generation == m.builds.generation && msg.query == m.builds.query && m.builds.pending {
			cmd := m.beginSearch(false)
			return m, cmd
		}
	case searchResultMsg:
		m.acceptSearch(msg)
	case SelectBuildMsg:
		cmd := m.selectBuild(msg.UpdateID)
		return m, cmd
	case ChangeArchitectureMsg:
		m.image.focus = 0
		cmd := m.changeArchitecture(msg.Architecture)
		m.syncArchitectureCursor()
		return m, cmd
	case languagesResultMsg:
		cmd := m.acceptLanguages(msg)
		return m, cmd
	case SelectLanguageMsg:
		cmd := m.selectLanguage(msg.Language)
		return m, cmd
	case editionsResultMsg:
		m.acceptEditions(msg)
		if m.area == Apps {
			return m, m.beginApps(false)
		}
	case ToggleEditionMsg:
		m.toggleEdition(msg.Edition)
		if m.area == Apps {
			return m, m.beginApps(false)
		}
	case RefreshMsg:
		var cmd tea.Cmd
		if m.area == Apps {
			cmd = m.beginApps(true)
		} else if m.area == Image && m.cfg.Image.UpdateID != "" {
			if m.image.focus == 2 && m.cfg.Image.Language != "" {
				cmd = m.beginEditions(true)
			} else {
				cmd = m.beginLanguages(true)
			}
		} else {
			cmd = m.beginSearch(true)
		}
		return m, cmd
	case imageFocusMsg:
		m.image.focus = msg.field
		return m.activate()
	case editionClickMsg:
		m.image.focus = 2
		m.image.editionCursor = msg.index
		m.toggleEdition(msg.edition)
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	case tea.MouseClickMsg:
		if msg.Button == tea.MouseLeft {
			_, hits := m.layout()
			for _, hit := range hits {
				if hit.contains(msg.X, msg.Y) {
					return m.Update(hit.msg)
				}
			}
		}
	case tea.MouseWheelMsg:
		if m.showTOML {
			if msg.Button == tea.MouseWheelUp {
				m.scrollTOML(-3)
			}
			if msg.Button == tea.MouseWheelDown {
				m.scrollTOML(3)
			}
		} else if !m.showHelp && !m.editing() {
			if msg.Button == tea.MouseWheelUp {
				m.move(-1)
			}
			if msg.Button == tea.MouseWheelDown {
				m.move(1)
			}
		}
	default:
		if m.editing() && !m.showHelp && !m.showTOML {
			return m.updateInput(msg)
		}
	}
	return m, nil
}

func cloneConfig(cfg config.Config) config.Config {
	cfg.Image.Editions = slices.Clone(cfg.Image.Editions)
	cfg.Apps.Include = slices.Clone(cfg.Apps.Include)
	cfg.Conversion.Drivers.Targets = slices.Clone(cfg.Conversion.Drivers.Targets)
	cfg.Conversion.Editions.Derived = slices.Clone(cfg.Conversion.Editions.Derived)
	cfg.Output.EditionOrder = slices.Clone(cfg.Output.EditionOrder)
	return cfg
}
