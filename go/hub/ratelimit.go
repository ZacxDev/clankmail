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

// allow reports whether every key has a token, and takes one from each only
// if so.
func allowAll(now int64, pairs ...limitPair) bool {
	for _, p := range pairs {
		p.l.mu.Lock()
	}
	defer func() {
		for _, p := range pairs {
			p.l.mu.Unlock()
		}
	}()
	bs := make([]*bucket, len(pairs))
	for i, p := range pairs {
		b := p.l.buckets[p.key]
		if b == nil {
			if len(p.l.buckets) >= maxBuckets {
				p.l.sweep(now)
			}
			b = &bucket{tokens: p.l.lim.Burst, last: now}
			p.l.buckets[p.key] = b
		}
		p.l.refill(b, now)
		if b.tokens < 1 {
			return false
		}
		bs[i] = b
	}
	for _, b := range bs {
		b.tokens--
	}
	return true
}

type limitPair struct {
	l   *limiter
	key string
}

func (l *limiter) sweep(now int64) {
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.lim.Burst {
			delete(l.buckets, k)
		}
	}
}
