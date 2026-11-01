package hub

import "sync"

// Limit is a token bucket: Burst tokens, refilled at PerSec per second.
type Limit struct {
	Burst  float64
	PerSec float64
}

// DefaultKeyLimit and DefaultIPLimit are the default-ON submit limits (§5:
// a hub that accepts unlimited posts is non-conforming). Keys are free to
// mint, so the per-IP limit is what bounds a key-rotating sender.
var (
	DefaultKeyLimit = Limit{Burst: 60, PerSec: 1}
	DefaultIPLimit  = Limit{Burst: 600, PerSec: 10}
)

// DefaultDigestKeyLimit and DefaultDigestIPLimit limit GET /v1/digest (§8.1),
// the one read that scans the channel logs. A digest reads at most
// digestScanBudget rows, so a caught-up reader needs one request per wake and
// a reader far behind pages with more:true at about one request every 2 s.
var (
	DefaultDigestKeyLimit = Limit{Burst: 30, PerSec: 0.5}
	DefaultDigestIPLimit  = Limit{Burst: 120, PerSec: 2}
)

type bucket struct {
	tokens float64
	last   int64 // ms
}

// limiter keys buckets by an arbitrary string. Full buckets are swept once the
// map grows past maxBuckets, so minting keys cannot grow memory without bound.
type limiter struct {
	mu      sync.Mutex
	lim     Limit
	buckets map[string]*bucket
}

const maxBuckets = 100000

func newLimiter(l Limit) *limiter { return &limiter{lim: l, buckets: map[string]*bucket{}} }

func (l *limiter) refill(b *bucket, now int64) {
	if now > b.last {
		b.tokens += float64(now-b.last) / 1000 * l.lim.PerSec
		if b.tokens > l.lim.Burst {
			b.tokens = l.lim.Burst
		}
		b.last = now
	}
}

// allow takes one token from key's bucket and reports whether it had one.
func (l *limiter) allow(now int64, key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			l.sweep(now)
		}
		b = &bucket{tokens: l.lim.Burst, last: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) sweep(now int64) {
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.lim.Burst {
			delete(l.buckets, k)
		}
	}
}
