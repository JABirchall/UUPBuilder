package catalog

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
func (systemClock) Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// A Retry-After beyond the bounded retry window stops this call instead of
// retrying earlier than the server permits. The caller can retry later.
func retryDelay(header string, attempt int, now time.Time) (time.Duration, bool) {
	const maximum = 2 * time.Minute
	header = strings.TrimSpace(header)
	if header != "" {
		if seconds, err := strconv.ParseUint(header, 10, 64); err == nil {
			if seconds > uint64(maximum/time.Second) {
				return 0, false
			}
			return time.Duration(seconds) * time.Second, true
		}
		// A decimal value too large for uint64 is still a server-requested
		// delay; never interpret overflow as permission for an early retry.
		if strings.Trim(header, "0123456789") == "" {
			return 0, false
		}
		if date, err := http.ParseTime(header); err == nil {
			delay := date.Sub(now)
			if delay > maximum {
				return 0, false
			}
			if delay < 0 {
				delay = 0
			}
			return delay, true
		}
	}
	return (500 * time.Millisecond) << attempt, true
}
