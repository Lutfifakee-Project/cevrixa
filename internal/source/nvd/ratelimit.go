package nvd

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// rateLimiter enforces a minimum interval between successive requests.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{interval: interval}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if r.interval <= 0 {
		return nil
	}

	r.mu.Lock()
	elapsed := time.Since(r.last)
	if elapsed < r.interval {
		wait := r.interval - elapsed
		r.mu.Unlock()
		fmt.Fprintf(os.Stderr, "nvd: rate limit — waiting %s\n", wait.Round(time.Second))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
		r.mu.Lock()
	}
	r.last = time.Now()
	r.mu.Unlock()
	return nil
}

// defaultInterval returns the minimum interval between NVD requests.
//
// NVD public limit: 5 requests per 30 seconds → 6s interval.
// With API key: 50 requests per 30 seconds → 0.6s interval.
func defaultInterval(hasAPIKey bool) time.Duration {
	if hasAPIKey {
		return 600 * time.Millisecond
	}
	return 6 * time.Second
}
