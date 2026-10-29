package tui

import (
	"slices"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

// buildGroup is presentation only. Its exact title/build key never replaces
// the retained UUID/revision records used for discovery and configuration.
type buildGroup struct {
	title, build string
	records      []catalog.Build
	matches      []catalog.Build
}

func groupBuilds(records []catalog.Build) []buildGroup {
	type key struct{ title, build string }
	indexes := make(map[key]int)
	var groups []buildGroup
	for _, b := range records {
		k := key{b.Title, b.Build}
		i, ok := indexes[k]
		if !ok {
			i = len(groups)
			indexes[k] = i
			groups = append(groups, buildGroup{title: b.Title, build: b.Build})
		}
		groups[i].records = append(groups[i].records, b)
	}
	return groups
}

func (s buildsState) visibleGroups() []buildGroup {
	var visible []buildGroup
	for _, group := range groupBuilds(s.records) {
		for _, b := range group.records {
			if s.matches(b) {
				group.matches = append(group.matches, b)
			}
		}
		if len(group.matches) > 0 {
			visible = append(visible, group)
		}
	}
	return visible
}

func (g buildGroup) contains(id string) bool {
	return slices.ContainsFunc(g.records, func(b catalog.Build) bool { return b.UpdateID == id })
}

func (g buildGroup) architectures() []model.Architecture {
	var choices []model.Architecture
	for _, b := range g.records {
		if !slices.Contains(choices, b.Architecture) {
			choices = append(choices, b.Architecture)
		}
	}
	slices.Sort(choices)
	return choices
}

// preferredBuild receives only eligible records. Prefer the requested target,
// keep an exact requested revision on that target, then use upstream order.
func preferredBuild(records []catalog.Build, arch model.Architecture, id string) catalog.Build {
	first := -1
	for i, b := range records {
		if b.Architecture != arch {
			continue
		}
		if first < 0 {
			first = i
		}
		if b.UpdateID == id {
			return b
		}
	}
	if first >= 0 {
		return records[first]
	}
	return records[0]
}

func (m Model) groupBuild(group buildGroup) catalog.Build {
	arch := m.builds.archFilter
	if arch == "" {
		arch = m.cfg.Image.Architecture
	}
	return preferredBuild(group.matches, arch, m.cfg.Image.UpdateID)
}

func (m Model) selectedGroup() (buildGroup, bool) {
	for _, group := range groupBuilds(m.builds.records) {
		for _, b := range group.records {
			if b.UpdateID == m.cfg.Image.UpdateID && b.Architecture == m.cfg.Image.Architecture {
				return group, true
			}
		}
	}
	return buildGroup{}, false
}

func (m Model) imageArchitectures() []model.Architecture {
	if group, ok := m.selectedGroup(); ok {
		return group.architectures()
	}
	return m.Architectures()
}
