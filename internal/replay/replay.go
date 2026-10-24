// Package replay provides a bounded, TTL-based "seen once" cache used to
// reject replayed OIDC nonces, login states and posture assertion IDs.
package replay

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

// ErrReplayed is returned when a value has already been consumed.
var ErrReplayed = errors.New("replay: value already used")

// ErrFull is returned when the cache is at capacity with unexpired entries.
// Failing closed (rejecting) is safer than evicting live entries, which would
// re-open a replay window.
var ErrFull = errors.New("replay: cache full")

// Cache remembers values until their expiry. All methods are safe for
// concurrent use. Insert and expiry sweeps are O(log n).
type Cache struct {
	mu    sync.Mutex
	max   int
	now   func() time.Time
	seen  map[string]time.Time
	queue expiryHeap
}

// New returns a cache holding at most max live entries. now may be nil.
func New(maxEntries int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	if maxEntries <= 0 {
		maxEntries = 100_000
	}
	return &Cache{max: maxEntries, now: now, seen: make(map[string]time.Time)}
}

// Use records value as consumed until expires. It returns ErrReplayed if the
// value is already present and unexpired.
func (c *Cache) Use(value string, expires time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweep(now)
	if exp, ok := c.seen[value]; ok && now.Before(exp) {
		return ErrReplayed
	}
	if len(c.seen) >= c.max {
		return ErrFull
	}
	c.seen[value] = expires
	heap.Push(&c.queue, entry{value: value, expires: expires})
	return nil
}

// Seen reports whether value is currently recorded.
func (c *Cache) Seen(value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.seen[value]
	return ok && c.now().Before(exp)
}

// Len returns the number of live entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweep(c.now())
	return len(c.seen)
}

func (c *Cache) sweep(now time.Time) {
	for c.queue.Len() > 0 && !now.Before(c.queue[0].expires) {
		e := heap.Pop(&c.queue).(entry)
		if exp, ok := c.seen[e.value]; ok && exp.Equal(e.expires) {
			delete(c.seen, e.value)
		}
	}
}

type entry struct {
	value   string
	expires time.Time
}

type expiryHeap []entry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(entry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	*h = old[:n-1]
	return e
}
