package tui

import (
	"reflect"
	"strings"
	"testing"
)

func TestFieldsRejectInvalidTypedInputWithoutChangingDraft(t *testing.T) {
	for _, invalid := range []struct{ key, value, diagnostic string }{
		{"conversion.cleanup", "yes", "true or false"},
		{"conversion.updates", "invented-policy", "choose"},
		{"conversion.drivers.targets", "os, invented-target", "unknown target"},
		{"downloads.parallel_files", "99999999999999999999999999999", "integer"},
		{"missing.setting", "auto", "unknown editable setting"},
	} {
		t.Run(invalid.key, func(t *testing.T) {
			m := browse(t)
			before := m.Snapshot()
			m = send(m, ConversionFieldChangedMsg{Key: invalid.key, Value: invalid.value})
			if !reflect.DeepEqual(m.cfg, before.Config) || m.revision != before.Revision || !strings.Contains(m.notice, invalid.diagnostic) {
				t.Fatalf("invalid typed input changed draft or hid diagnostic: %+v", m.Snapshot())
			}
		})
	}
}
