package replay

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func TestUseOnce(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(10, clk.now)
	if err := c.Use("n1", clk.t.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Use("n1", clk.t.Add(time.Minute)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay not detected: %v", err)
	}
	if !c.Seen("n1") || c.Seen("n2") {
		t.Fatal("Seen wrong")
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if c.Seen("n1") || c.Len() != 0 {
		t.Fatal("entry not expired")
	}
	if err := c.Use("n1", clk.t.Add(time.Minute)); err != nil {
		t.Fatalf("expired value should be reusable: %v", err)
	}
}

func TestCapacityFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(3, clk.now)
	for i := range 3 {
		if err := c.Use(fmt.Sprint(i), clk.t.Add(time.Duration(i+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Use("x", clk.t.Add(time.Minute)); !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull, got %v", err)
	}
	clk.t = clk.t.Add(1500 * time.Millisecond) // first entry expires
	if err := c.Use("x", clk.t.Add(time.Minute)); err != nil {
		t.Fatalf("slot not reclaimed: %v", err)
	}
	if c.Len() != 3 {
		t.Fatalf("len %d", c.Len())
	}
}

func TestReinsertAfterExpiryKeepsNewDeadline(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	c := New(10, clk.now)
	_ = c.Use("a", clk.t.Add(time.Second))
	clk.t = clk.t.Add(2 * time.Second)
	_ = c.Use("a", clk.t.Add(time.Hour)) // stale heap entry for old deadline remains
	clk.t = clk.t.Add(time.Second)
	if !c.Seen("a") {
		t.Fatal("stale heap entry evicted the renewed value")
	}
}

func TestConcurrentUseExactlyOnce(t *testing.T) {
	c := New(1000, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Use("same", time.Now().Add(time.Minute)) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("value accepted %d times", ok)
	}
}

func TestDefaults(t *testing.T) {
	c := New(0, nil)
	if c.max != 100_000 {
		t.Fatal("default max")
	}
}
