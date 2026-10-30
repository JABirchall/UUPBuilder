package tui

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
)

func TestAdditionalEditionsUseSelectedProFamily(t *testing.T) {
	for _, tc := range []struct {
		base string
		want []string
	}{
		{"PROFESSIONAL", []string{"ProfessionalWorkstation", "ProfessionalEducation", "Education", "Enterprise", "ServerRdsh", "IoTEnterprise", "IoTEnterpriseK"}},
		{"ProfessionalN", []string{"ProfessionalWorkstationN", "ProfessionalEducationN", "EducationN", "EnterpriseN"}},
	} {
		t.Run(tc.base, func(t *testing.T) {
			m := chosen(t)
			defer m.Close()
			m = send(m, ToggleEditionMsg{Edition: "professional"})
			m = send(m, editionsResultMsg{generation: m.image.editionGeneration, updateID: firstID, language: "en-us", editions: []catalog.Edition{{ID: tc.base, Name: "Pro"}, {ID: "Core", Name: "Home"}}})
			m = send(m, ToggleEditionMsg{Edition: tc.base})
			choices := m.editionChoices()
			if len(choices) != 2+len(tc.want) {
				t.Fatalf("wrong Pro family choices: %+v", choices)
			}
			for _, id := range tc.want {
				i := slices.IndexFunc(choices, func(e catalog.Edition) bool { return e.ID == id })
				if i < 0 || !strings.Contains(choices[i].Name, "from Pro") {
					t.Fatalf("missing derived choice %s: %+v", id, choices)
				}
				m = send(m, ToggleEditionMsg{Edition: id})
			}
			selection, settings, err := m.cfg.Request()
			if err != nil || !reflect.DeepEqual(selection.Editions, []string{tc.base}) || !reflect.DeepEqual(settings.Conversion.Editions.Derived, tc.want) || !m.Snapshot().ImageReady {
				t.Fatalf("additional editions not passed separately to build: selection=%+v derived=%v ready=%t err=%v", selection, settings.Conversion.Editions.Derived, m.Snapshot().ImageReady, err)
			}
			m = send(m, ConfigPathChangedMsg{Path: filepath.Join(t.TempDir(), "editions.toml")})
			m = finishConfigAction(t, m, SaveConfigMsg{})
			saved, err := config.Load(m.configActions.path)
			if err != nil || !reflect.DeepEqual(saved.Conversion.Editions.Derived, tc.want) || !reflect.DeepEqual(saved.Image.Editions, []string{tc.base}) {
				t.Fatalf("saved edition selection lost: %+v %v", saved, err)
			}
		})
	}
}

func TestAdditionalEditionRequiresSelectedBaseAndCanBeRemoved(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, ToggleEditionMsg{Edition: "EnterpriseN"})
	if len(m.cfg.Conversion.Editions.Derived) != 0 {
		t.Fatal("Pro offered an N derivative")
	}
	m = send(m, ToggleEditionMsg{Edition: "Enterprise"})
	if !reflect.DeepEqual(m.cfg.Conversion.Editions.Derived, []string{"Enterprise"}) {
		t.Fatal("Enterprise could not be selected")
	}
	m = send(m, ToggleEditionMsg{Edition: "core"})
	m = send(m, ToggleEditionMsg{Edition: "professional"})
	if m.Snapshot().ImageReady {
		t.Fatal("missing Pro base did not block continuation")
	}
	m = send(m, NavigateMsg{Area: Image})
	m.image.focus = 2
	m.image.editionCursor = len(m.editionChoices()) - 1
	if view := m.View().Content; !strings.Contains(view, "Enterprise") || !strings.Contains(view, "! unavailable") {
		t.Fatalf("unavailable derivative was hidden: %s", view)
	}
	m = send(m, key(tea.KeyEnter, ""))
	if m.ActiveArea() != Image {
		t.Fatal("continued with unavailable derivative")
	}
	m = send(m, ToggleEditionMsg{Edition: "enterprise"})
	if len(m.cfg.Conversion.Editions.Derived) != 0 || !m.Snapshot().ImageReady {
		t.Fatal("unavailable derivative could not be removed case-insensitively")
	}
	m = send(m, ToggleEditionMsg{Edition: "Enterprise"})
	if len(m.cfg.Conversion.Editions.Derived) != 0 {
		t.Fatal("Home offered a Pro derivative")
	}
}

func TestAdditionalEditionKeyboardSelectionAppearsInSummaryAndReview(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, NavigateMsg{Area: Image})
	choices := m.editionChoices()
	i := slices.IndexFunc(choices, func(e catalog.Edition) bool { return e.ID == "Enterprise" })
	if i < 0 {
		t.Fatal("Enterprise choice missing")
	}
	m.image.focus, m.image.editionCursor = 2, i
	beforeRevision, beforeApps := m.revision, m.apps.generation
	m = send(m, key(' ', " "))
	if !reflect.DeepEqual(m.cfg.Conversion.Editions.Derived, []string{"Enterprise"}) || m.revision != beforeRevision+1 || m.apps.generation <= beforeApps {
		t.Fatal("keyboard toggle did not select and invalidate the draft")
	}
	if view := m.View().Content; !strings.Contains(view, "[x] Enterprise") || !strings.Contains(view, "professional, Enterprise") {
		t.Fatalf("selected derivative missing from image/summary: %s", view)
	}
	m.buildAction.draft = BuildDraft{Config: cloneConfig(m.cfg), Revision: m.revision}
	var review strings.Builder
	for _, row := range m.reviewDetails(120) {
		review.WriteString(row.text)
	}
	if !strings.Contains(review.String(), "professional, Enterprise") {
		t.Fatalf("review omitted derived target: %s", review.String())
	}
}

func TestDirectEditionIsNotDuplicatedAsDerived(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, editionsResultMsg{generation: m.image.editionGeneration, updateID: firstID, language: "en-us", editions: []catalog.Edition{{ID: "professional", Name: "Pro"}, {ID: "ENTERPRISE", Name: "Enterprise"}}})
	var count int
	for _, choice := range m.editionChoices() {
		if strings.EqualFold(choice.ID, "Enterprise") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate direct/derived choice: %+v", m.editionChoices())
	}
	m = send(m, ToggleEditionMsg{Edition: "enterprise"})
	if !reflect.DeepEqual(m.cfg.Image.Editions, []string{"professional", "ENTERPRISE"}) || len(m.cfg.Conversion.Editions.Derived) != 0 {
		t.Fatalf("direct edition not selected using catalog ID: %+v", m.cfg)
	}
}

func TestAllAdditionalEditionsReachBuildAndRemainReadableInReview(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, editionsResultMsg{generation: m.image.editionGeneration, updateID: firstID, language: "en-us", editions: []catalog.Edition{{ID: "professional", Name: "Pro"}, {ID: "ProfessionalN", Name: "Pro N"}}})
	m = send(m, ToggleEditionMsg{Edition: "ProfessionalN"})
	want := []string{"ProfessionalWorkstation", "ProfessionalEducation", "Education", "Enterprise", "ServerRdsh", "IoTEnterprise", "IoTEnterpriseK", "ProfessionalWorkstationN", "ProfessionalEducationN", "EducationN", "EnterpriseN"}
	for _, id := range want {
		m = send(m, ToggleEditionMsg{Edition: id})
	}
	m = send(m, ConversionFieldChangedMsg{Key: "conversion.cleanup", Value: "false"})
	m = send(m, ConfigPathChangedMsg{Path: filepath.Join(t.TempDir(), "build.toml")})
	m.deps.Builder = preparedBuild{calls: new(int)}
	var check tea.Cmd
	m, check = step(m, BuildMsg{})
	if check == nil || !reflect.DeepEqual(m.buildAction.draft.Config.Conversion.Editions.Derived, want) || !reflect.DeepEqual(m.buildAction.draft.Config.Image.Editions, []string{"professional", "ProfessionalN"}) {
		t.Fatalf("build did not retain all targets after editing: %s %+v", m.notice, m.buildAction.draft.Config)
	}
	var review strings.Builder
	for _, row := range m.reviewDetails(70) {
		review.WriteString(row.text)
	}
	for _, id := range want {
		if !strings.Contains(review.String(), id) {
			t.Fatalf("review truncated selected edition %s: %s", id, review.String())
		}
	}
}

func TestAdditionalEditionsCanBeReachedInCompactView(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, tea.WindowSizeMsg{Width: 68, Height: 24})
	m = send(m, NavigateMsg{Area: Image})
	m.image.focus = 2
	for range 8 {
		m = send(m, key(tea.KeyDown, ""))
	}
	m = send(m, key(' ', " "))
	if !reflect.DeepEqual(m.cfg.Conversion.Editions.Derived, []string{"IoTEnterpriseK"}) {
		t.Fatal("last additional edition was unreachable by keyboard")
	}
	if view := m.View().Content; !strings.Contains(view, "[x] IoT Enterprise K") {
		t.Fatalf("focused edition did not scroll into view: %s", view)
	}
}

func TestOtherConfiguredDerivedEditionsStillReachSourceValidation(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, ToggleEditionMsg{Edition: "core"})
	m = send(m, ToggleEditionMsg{Edition: "professional"})
	m = send(m, ConversionFieldChangedMsg{Key: "conversion.editions.derived", Value: "CoreSingleLanguage"})
	if !m.Snapshot().ImageReady {
		t.Fatal("additional-edition offers became an allowlist for configured derivations")
	}
	m = send(m, NavigateMsg{Area: Image})
	m.image.focus, m.image.editionCursor = 2, len(m.editionChoices())-1
	if view := m.View().Content; !strings.Contains(view, "CoreSingleLanguage") || strings.Contains(view, "! unavailable") {
		t.Fatalf("configured derivative incorrectly claimed unavailable before source inspection: %s", view)
	}
	m = send(m, ToggleEditionMsg{Edition: "coresinglelanguage"})
	if len(m.cfg.Conversion.Editions.Derived) != 0 {
		t.Fatal("configured derivative could not be deselected")
	}
}

func TestSavedUnavailableDownloadIsNotMaskedByDerivedOffer(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	// Older/manual configurations can request a derived ID as a download.
	m.cfg.Image.Editions = append(m.cfg.Image.Editions, "Enterprise")
	m = send(m, NavigateMsg{Area: Image})
	m.image.focus = 2
	choices := m.editionChoices()
	m.image.editionCursor = slices.IndexFunc(choices, func(e catalog.Edition) bool { return e.ID == "Enterprise" })
	if m.Snapshot().ImageReady || !strings.Contains(m.View().Content, "! unavailable") {
		t.Fatalf("derived offer hid an unavailable download request: %s", m.View().Content)
	}
	m = send(m, ToggleEditionMsg{Edition: "Enterprise"})
	m = send(m, ToggleEditionMsg{Edition: "Enterprise"})
	if !m.Snapshot().ImageReady || !reflect.DeepEqual(m.cfg.Image.Editions, []string{"professional"}) || !reflect.DeepEqual(m.cfg.Conversion.Editions.Derived, []string{"Enterprise"}) {
		t.Fatal("unavailable download could not be reselected as a derivative")
	}
}
