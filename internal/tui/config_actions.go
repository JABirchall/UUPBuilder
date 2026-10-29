package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"uupbuilder/internal/config"
)

type configActionsState struct {
	path       string
	busy       bool
	generation uint64
	lastSave   config.SaveResult
}

func (m *Model) changeConfigPath(path string) {
	if path == m.configActions.path {
		return
	}
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00\r\n") {
		m.notice = "Config path: choose a nonempty file path without control characters."
		return
	}
	m.configActions.path = path
	m.revision++
	m.conversion.applicability = nil
	m.notice = "Config path changed; draft review is invalidated. No file has been written."
}

func (m Model) beginConfigAction(save bool) (tea.Model, tea.Cmd) {
	if m.configActions.busy {
		m.notice = "Wait for the current TOML action to finish."
		return m, nil
	}
	path := m.configActions.path
	if strings.TrimSpace(path) == "" {
		m.notice = "Choose a TOML config path before loading or saving."
		return m, nil
	}
	cfg := cloneConfig(m.cfg)
	if save {
		applied, issues := m.conversion.Apply(cfg)
		if len(issues) > 0 {
			m.notice = "Save failed: " + issues[0].Message
			return m, nil
		}
		cfg = applied
	}
	m.configActions.generation++
	m.configActions.busy = true
	generation, revision := m.configActions.generation, m.revision
	return m, func() tea.Msg {
		result := configActionResultMsg{generation: generation, revision: revision, path: path, save: save}
		if !save {
			result.cfg, result.err = config.Load(path)
			return result
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			result.err = fmt.Errorf("config path: %w", err)
			return result
		}
		if err := os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
			result.err = fmt.Errorf("create config directory: %w", err)
			return result
		}
		result.result, result.err = config.Save(absolute, cfg)
		return result
	}
}

func (m Model) acceptConfigAction(msg configActionResultMsg) (tea.Model, tea.Cmd) {
	if !m.configActions.busy || msg.generation != m.configActions.generation {
		return m, nil
	}
	m.configActions.busy = false
	if msg.save {
		m.configActions.lastSave = msg.result
		if msg.err != nil {
			m.notice = "Save failed: " + msg.err.Error()
		} else {
			m.notice = "Saved TOML: " + msg.path
			if msg.result.Normalized {
				m.notice += "; Normalized existing TOML formatting."
			}
		}
		if msg.result.BackupPath != "" {
			m.notice += "; Backup: " + msg.result.BackupPath
		}
		if msg.revision != m.revision || msg.path != m.configActions.path {
			m.notice += "; Saved the earlier draft/path; current draft is unchanged."
		}
		return m, nil
	}
	if msg.err != nil {
		m.notice = "Load failed: " + msg.err.Error()
		return m, nil
	}
	if msg.revision != m.revision || msg.path != m.configActions.path {
		m.notice = "Load discarded: draft or config path changed while reading."
		return m, nil
	}
	producer := m.deps.Catalog
	appProducer := m.deps.AppCatalog
	if msg.cfg.Catalog.Endpoint != m.cfg.Catalog.Endpoint {
		if appProducer != nil || m.deps.AppCatalogFactory != nil {
			if m.deps.AppCatalogFactory == nil {
				m.notice = "Load failed: catalog.endpoint changed, but the injected app catalogue cannot be recomposed."
				return m, nil
			}
			appProducer = m.deps.AppCatalogFactory(msg.cfg.Catalog.Endpoint)
			if appProducer == nil {
				m.notice = "Load failed: catalog.endpoint app factory returned no catalogue."
				return m, nil
			}
		}
		if m.deps.CatalogFactory == nil {
			m.notice = "Load failed: catalog.endpoint changed, but the injected catalogue cannot be recomposed."
			return m, nil
		}
		producer = m.deps.CatalogFactory(msg.cfg.Catalog.Endpoint)
		if producer == nil {
			m.notice = "Load failed: catalog.endpoint factory returned no catalogue."
			return m, nil
		}
	}
	if m.builds.cancel != nil {
		m.builds.cancel()
	}
	m.builds.generation++
	m.builds.records = nil
	m.builds.status = requestStatus{}
	m.builds.cursor = 0
	m.invalidateSource()
	m.source = nil
	m.cfg = cloneConfig(msg.cfg)
	m.deps.Catalog = producer
	m.deps.AppCatalog = appProducer
	m.conversion = NewConversionModel(m.cfg, nil)
	m.revision++
	m.appsUnchecked = m.cfg.Image.UpdateID != ""
	m.notice = "Loaded TOML: " + msg.path + "; image choices and settings applicability need validation."
	search := m.beginSearch(false)
	if m.cfg.Image.UpdateID != "" {
		return m, tea.Batch(search, m.beginLanguages(false))
	}
	return m, search
}
