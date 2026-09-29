package nvd

import (
	"context"
	"testing"
	"time"
)

func TestDefaultInterval(t *testing.T) {
	if d := defaultInterval(true); d != 600*time.Millisecond {
		t.Fatalf("with key = %v", d)
	}
	if d := defaultInterval(false); d != 6*time.Second {
		t.Fatalf("no key = %v", d)
	}
}

func TestRateLimiterZeroInterval(t *testing.T) {
	r := newRateLimiter(0)
	start := time.Now()
	if err := r.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("zero interval should not wait")
	}
}

func TestRateLimiterEnforcesInterval(t *testing.T) {
	r := newRateLimiter(200 * time.Millisecond)
	if err := r.wait(context.Background()); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	start := time.Now()
	if err := r.wait(context.Background()); err != nil {
		t.Fatalf("second wait: %v", err)
	}
	if time.Since(start) < 180*time.Millisecond {
		t.Fatalf("expected ~200ms wait, got %v", time.Since(start))
	}
}
