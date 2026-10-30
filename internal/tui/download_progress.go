package tui

import (
	"fmt"
	"slices"
	"strings"

	"uupbuilder/internal/model"
)

const maxDownloadProgress = 128
const downloadStopped model.DownloadState = "stopped"

type downloadProgress struct {
	key, name        string
	state            model.DownloadState
	completed, total *int64
}

func (p downloadProgress) active() bool {
	switch p.state {
	case model.DownloadCompleted, model.DownloadFailed, model.DownloadCancelled, downloadStopped:
		return false
	}
	return true
}

func copyByteCounter(value *int64) *int64 {
	if value == nil || *value < 0 {
		return nil
	}
	n := *value
	return &n
}

func (b *buildActionState) acceptDownload(event model.Event) bool {
	if event.Kind != model.EventBytes || event.Download == nil && event.CompletedBytes == nil && event.TotalBytes == nil {
		return false
	}
	name := boundedText(event.Message, 512)
	if name == "" {
		name = boundedText(event.StageID, 120)
	}
	if name == "" {
		name = "Download"
	}
	key := "bytes:" + boundedText(event.StageID, 120) + ":" + name
	state := model.DownloadTransferring
	if event.Download != nil {
		if event.Download.Name != "" {
			name = boundedText(event.Download.Name, 512)
		}
		if event.Download.ID != "" {
			key = "file:" + boundedText(event.JobID, 128) + ":" + boundedText(event.Download.ID, 256)
		}
		switch event.Download.State {
		case model.DownloadChecking, model.DownloadTransferring, model.DownloadRetrying, model.DownloadVerifying, model.DownloadCompleted, model.DownloadFailed, model.DownloadCancelled:
			state = event.Download.State
		}
	}
	if state == model.DownloadCompleted {
		for i := range b.downloads {
			if b.downloads[i].key == key {
				b.downloads = slices.Delete(b.downloads, i, i+1)
				break
			}
		}
		return true
	}
	entry := downloadProgress{key: key, name: name, state: state, completed: copyByteCounter(event.CompletedBytes), total: copyByteCounter(event.TotalBytes)}
	for i := range b.downloads {
		if b.downloads[i].key == key {
			b.downloads[i] = entry
			return true
		}
	}
	if len(b.downloads) == maxDownloadProgress {
		// Diagnostic history yields to active transfers. Even a caller with an
		// extreme concurrency setting cannot grow retained state indefinitely.
		evict := -1
		for i, old := range b.downloads {
			if !old.active() {
				evict = i
				break
			}
		}
		if evict == -1 {
			if !entry.active() {
				return true
			}
			evict = 0
		}
		b.downloads = append(b.downloads[:evict], b.downloads[evict+1:]...)
	}
	b.downloads = append(b.downloads, entry)
	return true
}

func (b *buildActionState) settleDownloads(state model.DownloadState) {
	for i := range b.downloads {
		if b.downloads[i].active() {
			b.downloads[i].state = state
		}
	}
}

func byteSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	value := float64(n) / 1024
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 && n%1024 == 0 {
		return fmt.Sprintf("%.0f %s", value, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

func (p downloadProgress) label() string {
	switch p.state {
	case model.DownloadChecking:
		return "Checking cache"
	case model.DownloadRetrying:
		return "Retrying"
	case model.DownloadVerifying:
		return "Verifying"
	case model.DownloadCompleted:
		return "Completed"
	case model.DownloadFailed:
		return "Failed"
	case model.DownloadCancelled:
		return "Cancelled"
	case downloadStopped:
		return "Stopped"
	default:
		return "Downloading"
	}
}

func (p downloadProgress) rows(width int) []row {
	width = max(0, width)
	completed, total := "unknown", "unknown"
	if p.completed != nil {
		completed = byteSize(*p.completed)
	}
	if p.total != nil {
		total = byteSize(*p.total)
	}
	sizes := completed + " / " + total
	percent, ratio := " --%", float64(-1)
	if p.state == model.DownloadCompleted {
		ratio = 1
	} else if p.completed != nil && p.total != nil && *p.total > 0 {
		ratio = min(1, float64(*p.completed)/float64(*p.total))
	}
	if ratio >= 0 {
		n := int(ratio * 100)
		if p.state != model.DownloadCompleted && p.completed != nil && p.total != nil && *p.completed < *p.total {
			n = min(n, 99)
		}
		percent = fmt.Sprintf("%3d%%", n)
	}
	bar := func(cells int) string {
		cells = max(1, cells)
		if ratio < 0 {
			return "[" + strings.Repeat("?", cells) + "]"
		}
		filled := min(cells, int(ratio*float64(cells)))
		return "[" + strings.Repeat("#", filled) + strings.Repeat("-", cells-filled) + "]"
	}
	label := p.label()
	nameLine := label
	if width > len(label)+3 {
		nameLine = fit(p.name, width-len(label)-3) + " · " + label
	}
	rows := []row{{text: fit(nameLine, width)}}
	if width < 36 {
		return append(rows, row{text: fit(bar(width-len(percent)-3)+" "+percent, width)}, row{text: fit(sizes, width)})
	}
	return append(rows, row{text: fit(bar(width-len(percent)-len(sizes)-4)+" "+percent+" "+sizes, width)})
}

func (b buildActionState) downloadRows(width, budget int) []row {
	if len(b.downloads) == 0 || budget <= 0 {
		return nil
	}
	// Show active files first, then the most recent bounded diagnostic history.
	ordered := make([]downloadProgress, 0, len(b.downloads))
	active := 0
	for _, p := range b.downloads {
		if p.active() {
			ordered = append(ordered, p)
			active++
		}
	}
	for i := len(b.downloads) - 1; i >= 0; i-- {
		if !b.downloads[i].active() {
			ordered = append(ordered, b.downloads[i])
		}
	}
	perFile := 2
	if width < 36 {
		perFile = 3
	}
	count := min(len(ordered), budget/perFile)
	if count < len(ordered) && budget >= perFile+1 {
		count = (budget - 1) / perFile
	}
	var rows []row
	for _, p := range ordered[:count] {
		rows = append(rows, p.rows(width)...)
	}
	if count < len(ordered) && len(rows) < budget {
		rows = append(rows, row{text: fit(fmt.Sprintf("Downloads: %d active · %d recent · %d more", active, len(ordered)-active, len(ordered)-count), width)})
	}
	return rows
}
