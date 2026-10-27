package metadata

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Synthetic adversarial XML: comments force separate CharData tokens within
// one node. The largest regression input is only about 81 KiB, not a near-limit
// document. Preserve its full text while rejecting quadratic allocation growth.
func commentSplitWIM(fragments int) []byte {
	return []byte(`<WIM><IMAGE INDEX="1"><NAME>` + strings.Repeat(strings.Repeat("x", 150)+`<!--x-->`, fragments) + `</NAME></IMAGE></WIM>`)
}

func measuredXMLAllocation(t *testing.T, data []byte, fragments int, limits Limits) uint64 {
	t.Helper()
	// This test is deliberately not parallel. A single parse per size keeps the
	// broken implementation's reproduction below roughly 25 MiB of allocation;
	// broad growth/budget thresholds tolerate small runtime background activity.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	root, err := parseXML(context.Background(), data, limits)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if got := root.child("IMAGE").child("NAME").text(); got != strings.Repeat("x", 150*fragments) {
		t.Fatalf("fragmented name text lost: got %d bytes, want %d", len(got), 150*fragments)
	}
	runtime.KeepAlive(root)
	return after.TotalAlloc - before.TotalAlloc
}

// Immutable-string append causes approximately 16x allocation when fragments
// grow 4x. Amortized-linear accumulation must stay below a generous 6x growth
// bound and a 32-bytes-allocated/input-byte ceiling on this fixed XML shape.
func TestCommentSplitXMLTextAllocationIsLinear(t *testing.T) {
	limits, err := inspectionLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	smallInput, largeInput := commentSplitWIM(128), commentSplitWIM(512)
	if int64(len(largeInput)) > limits.MaxDocumentBytes {
		t.Fatal("regression input exceeds default metadata byte bound")
	}
	small := measuredXMLAllocation(t, smallInput, 128, limits)
	large := measuredXMLAllocation(t, largeInput, 512, limits)
	t.Logf("comment-split XML: input %d -> %d bytes; allocated %d -> %d bytes (%.2fx for 4x text)", len(smallInput), len(largeInput), small, large, float64(large)/float64(small))
	if large > 6*small {
		t.Fatalf("superlinear allocation growth: %d > 6 * %d", large, small)
	}
	if large > 32*uint64(len(largeInput)) {
		t.Fatalf("fragmented text exceeded linear allocation budget: %d bytes allocated for %d input bytes", large, len(largeInput))
	}
}

type cancelAfterChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *cancelAfterChecks) Err() error {
	if c.remaining == 0 {
		c.cancel()
	} else {
		c.remaining--
	}
	return c.Context.Err()
}

// Accumulating chunks must not bypass token limits or cancellation checks
// between tokens. Cancellation is deterministic and does not use timing races.
func TestCommentSplitXMLTextHonorsLimitsAndCancellation(t *testing.T) {
	limits, err := inspectionLimits(Limits{MaxXMLTokens: 100})
	if err != nil {
		t.Fatal(err)
	}
	data := commentSplitWIM(128)
	if _, err := parseXML(context.Background(), data, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("token limit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	canceling := &cancelAfterChecks{Context: ctx, cancel: cancel, remaining: 20}
	if _, err := parseXML(canceling, data, limits); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-parse cancellation: %v", err)
	}
}

// Run with -benchtime=1x -benchmem for a bounded before/after allocation sample.
func BenchmarkCommentSplitXMLText(b *testing.B) {
	for _, fragments := range []int{64, 128, 256, 512} {
		b.Run(fmt.Sprintf("fragments=%d", fragments), func(b *testing.B) {
			data := commentSplitWIM(fragments)
			limits, err := inspectionLimits(Limits{})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				root, err := parseXML(context.Background(), data, limits)
				if err != nil {
					b.Fatal(err)
				}
				runtime.KeepAlive(root)
			}
		})
	}
}
