package tui

import (
	"fmt"
	"slices"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

const configControlCount = 3 // path, load, save

// ConversionModel edits requested policies. Applicability is observational;
// unknown values remain unknown until the owning resolver supplies evidence.
type ConversionModel struct {
	fields        []settingField
	applicability []model.SettingApplicability
	cursor        int
	input         textinput.Model
}

func NewConversionModel(cfg config.Config, applicability []model.SettingApplicability) ConversionModel {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 32768
	input.SetWidth(60)
	input.SetVirtualCursor(true)
	input.SetStyles(textinput.Styles{Focused: textinput.StyleState{Text: lipgloss.NewStyle()}, Blurred: textinput.StyleState{Text: lipgloss.NewStyle()}})
	editor := ConversionModel{fields: conversionFields(), applicability: slices.Clone(applicability), input: input}
	for i := range editor.fields {
		editor.fields[i].value = editor.fields[i].read(cfg)
	}
	return editor
}

func (c ConversionModel) Apply(cfg config.Config) (config.Config, []model.Diagnostic) {
	next := cloneConfig(cfg)
	for _, field := range c.fields {
		if err := field.write(&next, field.value); err != nil {
			return cfg, []model.Diagnostic{settingDiagnostic(err)}
		}
	}
	if err := next.Validate(); err != nil {
		return next, []model.Diagnostic{settingDiagnostic(err)}
	}
	return next, nil
}
func settingDiagnostic(err error) model.Diagnostic {
	key, _, _ := strings.Cut(err.Error(), ":")
	return model.Diagnostic{Code: "settings.invalid", Severity: model.SeverityError, PolicyKey: key, Location: model.SourceLocation{Key: key}, Message: err.Error()}
}
func (c *ConversionModel) set(key, value string) error {
	for i := range c.fields {
		f := &c.fields[i]
		if f.key != key {
			continue
		}
		var parsed config.Config
		if err := f.write(&parsed, value); err != nil {
			return err
		}
		value = f.read(parsed)
		if f.value != value {
			f.value = value
			c.applicability = nil
		}
		return nil
	}
	return fmt.Errorf("unknown editable setting %q", key)
}
func (c ConversionModel) detail(key string) string {
	for _, field := range c.fields {
		if field.key != key {
			continue
		}
		text := "requested: " + field.value
		// Scope exclusions precede observational applicability. A loaded legacy
		// request remains intact even if an old resolver called it supported.
		switch key {
		case "conversion.include_winre", "conversion.winre_updates":
			return text + " | excluded: recovery/WinRE work; legacy value retained."
		case "conversion.drivers.targets":
			if slices.Contains(strings.Split(strings.ReplaceAll(field.value, " ", ""), ","), "winre") {
				return text + " | excluded: WinRE driver targets; other targets need applicability checks."
			}
		case "output.kind":
			if field.value != string(model.OutputISO) {
				return text + " | excluded: standalone image/directory output; choose iso."
			}
			text += " | ISO file deliverable"
		case "output.image_format":
			text += " | image inside ISO; standalone images excluded"
		}
		for _, applicability := range c.applicability {
			if applicability.Key != key || applicability.RequestedValue != field.value {
				continue
			}
			state := "supported"
			if !applicability.Supported {
				state = "unsupported"
			}
			effective := applicability.EffectiveValue
			if effective == "" {
				effective = "unresolved"
			}
			return text + " | effective: " + effective + " | " + state + "; " + applicability.Reason
		}
		return text + " | effective: unchecked (source applicability unresolved)"
	}
	return ""
}

func (m *Model) changeConversion(key, value string) {
	before := -1
	for i, field := range m.conversion.fields {
		if field.key == key {
			before = i
			break
		}
	}
	original := ""
	if before >= 0 {
		original = m.conversion.fields[before].value
	}
	if err := m.conversion.set(key, value); err != nil {
		m.notice = err.Error()
		return
	}
	if before >= 0 && m.conversion.fields[before].value == original {
		return
	}
	next, diagnostics := m.conversion.Apply(m.cfg)
	// Syntactically typed requests can be structurally incomplete across fields
	// (e.g. explicit proxy needs an origin). Keep them editable and block Save.
	m.cfg = next
	m.revision++
	m.notice = "Requested settings changed; applicability is unchecked."
	if len(diagnostics) > 0 {
		m.notice = diagnostics[0].Message
	}
}

func (m Model) activateConversion() (tea.Model, tea.Cmd) {
	c := &m.conversion
	if c.cursor == 1 {
		return m.Update(LoadConfigMsg{})
	}
	if c.cursor == 2 {
		return m.Update(SaveConfigMsg{})
	}
	value := m.configActions.path
	if c.cursor >= configControlCount {
		field := c.fields[c.cursor-configControlCount]
		if len(field.choices) > 0 {
			next := (slices.Index(field.choices, field.value) + 1) % len(field.choices)
			return m.Update(ConversionFieldChangedMsg{Key: field.key, Value: field.choices[next]})
		}
		value = field.value
	}
	c.input.SetValue(value)
	c.input.CursorEnd()
	cmd := c.input.Focus()
	return m, cmd
}
func (m Model) updateConversionInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc":
			m.conversion.input.Blur()
			return m, nil
		case "enter":
			value := m.conversion.input.Value()
			m.conversion.input.Blur()
			if m.conversion.cursor == 0 {
				return m.Update(ConfigPathChangedMsg{Path: value})
			}
			field := m.conversion.fields[m.conversion.cursor-configControlCount]
			return m.Update(ConversionFieldChangedMsg{Key: field.key, Value: value})
		}
	}
	var cmd tea.Cmd
	m.conversion.input, cmd = m.conversion.input.Update(msg)
	return m, cmd
}

func (m Model) conversionRows(width, height int) []row {
	c := m.conversion
	rows := []row{{text: heading.Render("ISO conversion and TOML settings")}}
	if c.cursor >= configControlCount {
		field := c.fields[c.cursor-configControlCount]
		rows = append(rows, row{text: accent.Render(terminalText(field.group + " · " + field.key))})
		for _, line := range wrapped(terminalText(c.detail(field.key)), width, 2) {
			rows = append(rows, row{text: muted.Render(line)})
		}
	} else {
		for _, line := range wrapped("TOML: "+terminalText(m.configActions.path), width, 2) {
			rows = append(rows, row{text: muted.Render(line)})
		}
		rows = append(rows, row{text: "Load replaces draft; save validates and creates its directory."})
		if m.configActions.lastSave.Normalized {
			rows = append(rows, row{text: "Last save: Normalized existing TOML formatting."})
		}
		if backup := m.configActions.lastSave.BackupPath; backup != "" {
			for _, line := range wrapped("Backup: "+terminalText(backup), width, 4) {
				rows = append(rows, row{text: line})
			}
		}
	}
	if m.configActions.busy {
		rows = append(rows, row{text: "TOML action in progress..."})
	}
	rowHeight := 1
	if height >= 14 {
		rowHeight = 3
		rows = append(rows, row{})
	}
	// Keep the focused bordered control visible even when a path/save result
	// consumes the available explanatory space.
	if height > 0 && len(rows) > height-rowHeight {
		rows = rows[:max(0, height-rowHeight)]
	}
	count := max(1, (height-len(rows))/rowHeight)
	start := max(0, c.cursor-count+1)
	for i := start; i < min(configControlCount+len(c.fields), start+count); i++ {
		label, text := "", ""
		switch i {
		case 0:
			label, text = "TOML · Config path", terminalText(m.configActions.path)
		case 1:
			label, text = "TOML", "Load selected file"
		case 2:
			label, text = "TOML", "Save selected file"
		default:
			field := c.fields[i-configControlCount]
			label, text = field.group+" · "+field.label, terminalText(field.value)
		}
		prefix := ""
		if i == c.cursor {
			if rowHeight == 3 {
				prefix = "> "
			}
			if c.input.Focused() {
				label = "Edit · " + label
				text = inputView(c.input, width-7)
			}
		}
		rows = append(rows, controlRows(label, prefix+text, width, i == c.cursor, rowHeight == 1, conversionFocusMsg{index: i})...)
	}
	return rows
}
