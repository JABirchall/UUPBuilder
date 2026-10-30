package model

import "time"

type EventKind string

const (
	EventStage      EventKind = "stage"
	EventBytes      EventKind = "bytes"
	EventItems      EventKind = "items"
	EventLog        EventKind = "log"
	EventWarning    EventKind = "warning"
	EventError      EventKind = "error"
	EventCheckpoint EventKind = "checkpoint"
)

// Nil counters mean unknown, including a nil total for indeterminate progress.
// Emit delivery is observational; durable journal commits happen independently.
type Event struct {
	JobID          string            `json:"job_id"`
	StageID        string            `json:"stage_id"`
	Kind           EventKind         `json:"kind"`
	Message        string            `json:"message"`
	CompletedBytes *int64            `json:"completed_bytes,omitempty"`
	TotalBytes     *int64            `json:"total_bytes,omitempty"`
	Download       *DownloadProgress `json:"download,omitempty"`
	CompletedItems *int64            `json:"completed_items,omitempty"`
	TotalItems     *int64            `json:"total_items,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

type DownloadState string

const (
	DownloadChecking     DownloadState = "checking"
	DownloadTransferring DownloadState = "downloading"
	DownloadRetrying     DownloadState = "retrying"
	DownloadVerifying    DownloadState = "verifying"
	DownloadCompleted    DownloadState = "completed"
	DownloadFailed       DownloadState = "failed"
	DownloadCancelled    DownloadState = "cancelled"
)

// DownloadProgress identifies a single logical destination across retries and
// resume. Name is the frozen relative destination, never a runtime locator.
// Completed is emitted only after integrity verification and cache publication.
// The enclosing Event carries the nullable byte counters for older consumers.
type DownloadProgress struct {
	ID    string        `json:"id"`
	Name  string        `json:"name"`
	State DownloadState `json:"state"`
}

// The coordinator supplies a thread-safe sink; producers may call concurrently.
type Emit func(Event)

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

type SourceLocation struct {
	File   string `json:"file,omitempty"`
	Key    string `json:"key,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type Diagnostic struct {
	Code      string         `json:"code"`
	Severity  Severity       `json:"severity"`
	Location  SourceLocation `json:"location"`
	Message   string         `json:"message"`
	Selection *Selection     `json:"selection,omitempty"`
	PolicyKey string         `json:"policy_key,omitempty"`
}

// RequestedValue and EffectiveValue contain canonical public policy values,
// never a credential or signed URL. Unsupported explicit requests retain their
// original value and receive Supported=false plus a concrete Reason.
type SettingApplicability struct {
	Key            string `json:"key"`
	RequestedValue string `json:"requested_value"`
	EffectiveValue string `json:"effective_value"`
	Supported      bool   `json:"supported"`
	Automatic      bool   `json:"automatic"`
	Reason         string `json:"reason"`
}
