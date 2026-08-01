package cmd

import (
	"fmt"
	"sync"
	"testing"
)

func TestBlockStateConcurrent(t *testing.T) {
	bs := newBlockState()

	var wg sync.WaitGroup
	const workers = 100
	const opsPerWorker = 200

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				ip := fmt.Sprintf("10.0.%d.%d", id, i%256)
				switch i % 4 {
				case 0:
					bs.setBlocked(ip)
				case 1:
					bs.isBlocked(ip)
				case 2:
					bs.removeBlocked(ip)
				case 3:
					bs.count()
				}
			}
		}(w)
	}

	wg.Wait()

	bs2 := newBlockState()
	bs2.setBlocked("192.168.1.1")
	bs2.setBlocked("192.168.1.2")
	if !bs2.isBlocked("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be blocked")
	}
	bs2.removeBlocked("192.168.1.1")
	if bs2.isBlocked("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be unblocked")
	}
	if bs2.count() != 1 {
		t.Errorf("expected count=1, got %d", bs2.count())
	}
}
