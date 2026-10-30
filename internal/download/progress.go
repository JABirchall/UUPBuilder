//go:build windows

package download

import (
	"context"
	"errors"
	"time"

	"uupbuilder/internal/model"
)

// A reporter belongs to one fetch, so parallel transfers never share mutable
// counters. Sinks may still be invoked concurrently by different reporters.
type progressReporter struct {
	manager   *Manager
	payload   model.Payload
	emit      model.Emit
	id        string
	completed int64
	lastData  time.Time
	hasData   bool
}

func (m *Manager) newProgress(payload model.Payload, emit model.Emit) *progressReporter {
	p := &progressReporter{manager: m, payload: payload, emit: emit, id: hashString(payload.Identity.Key() + "\n" + payload.Destination)}
	p.send(model.DownloadChecking)
	return p
}

func (p *progressReporter) send(state model.DownloadState) {
	if p.emit == nil {
		return
	}
	completed, total := p.completed, p.payload.Identity.Size
	p.emit(model.Event{
		JobID: p.manager.opts.Job.Identity().JobID, StageID: "downloads", Kind: model.EventBytes,
		Message:        "Downloading " + p.payload.Destination,
		Download:       &model.DownloadProgress{ID: p.id, Name: p.payload.Destination, State: state},
		CompletedBytes: &completed, TotalBytes: &total, Timestamp: p.manager.opts.Now(),
	})
}

func (p *progressReporter) start(offset int64) {
	p.completed = offset
	p.hasData = false
	p.send(model.DownloadTransferring)
}

func (p *progressReporter) advance(completed int64) {
	p.completed = completed
	now := p.manager.opts.Now()
	if !p.hasData || now.Sub(p.lastData) >= 100*time.Millisecond || completed == p.payload.Identity.Size {
		state := model.DownloadTransferring
		if completed == p.payload.Identity.Size {
			state = model.DownloadVerifying
		}
		p.send(state)
		p.lastData, p.hasData = now, true
	}
}

func (p *progressReporter) finish(err error) {
	state := model.DownloadCompleted
	if err == nil {
		p.completed = p.payload.Identity.Size
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrClosed) {
		state = model.DownloadCancelled
	} else {
		state = model.DownloadFailed
	}
	p.send(state)
}
