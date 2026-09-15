package ndredgev02

import (
	"fmt"
	"sync"
	"testing"
)

func obs(id, source, target, group string, port int, ts float64) Observation {
	return Observation{
		EventID: id, TenantID: "tenant-1", SensorID: "sensor-1", Epoch: "epoch-1",
		SourceID: source, TargetID: target, DependencyGroup: group,
		DestinationPort: port, Protocol: "TCP", Outcome: "REFUSED", TimestampUnix: ts,
		TrustLevel: "SYNTHETIC", Authorization: "NOT_GRANTED", Mode: "SYNTHETIC",
	}
}

func findWindow(t *testing.T, snap MultiWindowSnapshot, seconds int) WindowSnapshot {
	t.Helper()
	for _, item := range snap.Windows {
		if item.WindowSeconds == seconds {
			return item
		}
	}
	t.Fatalf("window %d missing", seconds)
	return WindowSnapshot{}
}

func TestFixedMultiWindowSet(t *testing.T) {
	a, err := NewAccumulator(32, 8)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := a.Observe(obs("a", "src-1", "host-1", "g1", 80, 1000), 1001)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Windows) != 6 {
		t.Fatalf("windows=%d", len(snap.Windows))
	}
	for i, want := range []int{5, 30, 300, 3600, 21600, 86400} {
		if snap.Windows[i].WindowSeconds != want {
			t.Fatalf("window[%d]=%d", i, snap.Windows[i].WindowSeconds)
		}
	}
	if snap.Authorization != "NOT_GRANTED" || snap.Mode != "SYNTHETIC" {
		t.Fatal("authority/mode invariant broken")
	}
}

func TestBurstVisibleInShortWindows(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	var snap MultiWindowSnapshot
	var err error
	for i := 0; i < 4; i++ {
		snap, err = a.Observe(obs(fmt.Sprintf("e-%d", i), "src-1", "host-1", "g1", 20+i, 1000+float64(i)), 1004)
		if err != nil {
			t.Fatal(err)
		}
	}
	w5 := findWindow(t, snap, 5)
	if w5.ObservationCount != 4 || w5.Burst5sCount != 4 || w5.UniquePorts != 4 {
		t.Fatalf("unexpected 5s window: %+v", w5)
	}
}

func TestLowAndSlowSurvivesLongWindow(t *testing.T) {
	a, _ := NewAccumulator(64, 8)
	for i, ts := range []float64{1000, 1600, 2200} {
		if _, err := a.Observe(obs(fmt.Sprintf("e-%d", i), "src-1", fmt.Sprintf("host-%d", i), "scan", 80, ts), ts); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := a.Observe(obs("e-3", "src-1", "host-3", "scan", 80, 2800), 2800)
	if err != nil {
		t.Fatal(err)
	}
	if findWindow(t, snap, 30).ObservationCount != 1 {
		t.Fatalf("short window should contain only latest observation: %+v", findWindow(t, snap, 30))
	}
	w3600 := findWindow(t, snap, 3600)
	if w3600.ObservationCount != 4 || !w3600.LowAndSlow || !snap.LongHorizonOnly {
		t.Fatalf("low-and-slow not preserved: snap=%+v w=%+v", snap, w3600)
	}
}

func TestReplayRejected(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	o := obs("same", "src-1", "host-1", "g1", 80, 1000)
	if _, err := a.Observe(o, 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "REPLAY" {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestConflictingReplayStillRejected(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	o := obs("same", "src-1", "host-1", "g1", 80, 1000)
	if _, err := a.Observe(o, 1001); err != nil {
		t.Fatal(err)
	}
	o.TargetID = "host-2"
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "REPLAY" {
		t.Fatalf("conflicting replay accepted: %v", err)
	}
}

func TestLiveInputDisabled(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	o := obs("a", "src-1", "host-1", "g1", 80, 1000)
	o.TrustLevel = "AUTHENTICATED"
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "LIVE_INPUT_DISABLED" {
		t.Fatalf("live input accepted: %v", err)
	}
}

func TestAuthorityForbidden(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	o := obs("a", "src-1", "host-1", "g1", 80, 1000)
	o.Authorization = "GRANTED"
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "AUTHORITY_FORBIDDEN" {
		t.Fatalf("authority accepted: %v", err)
	}
}

func TestCrossTenantIsolation(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	first := obs("a", "src-1", "host-1", "g1", 80, 1000)
	if _, err := a.Observe(first, 1001); err != nil {
		t.Fatal(err)
	}
	second := obs("b", "src-1", "host-2", "g2", 81, 1000)
	second.TenantID = "tenant-2"
	snap, err := a.Observe(second, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if findWindow(t, snap, 300).ObservationCount != 1 {
		t.Fatalf("cross-tenant contamination: %+v", snap)
	}
}

func TestOutOfOrderWithinWindowAccepted(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	if _, err := a.Observe(obs("new", "src-1", "host-1", "g1", 80, 1200), 1200); err != nil {
		t.Fatal(err)
	}
	snap, err := a.Observe(obs("old", "src-1", "host-2", "g2", 81, 1100), 1200)
	if err != nil {
		t.Fatal(err)
	}
	w300 := findWindow(t, snap, 300)
	if w300.ObservationCount != 2 || w300.SpanSeconds != 100 {
		t.Fatalf("out-of-order aggregation wrong: %+v", w300)
	}
}

func TestEvidenceRefsBounded(t *testing.T) {
	a, _ := NewAccumulator(64, 8)
	var snap MultiWindowSnapshot
	var err error
	for i := 0; i < 40; i++ {
		snap, err = a.Observe(obs(fmt.Sprintf("e-%02d", i), "src-1", fmt.Sprintf("host-%d", i), "g", 100+i, 1000+float64(i)), 1040)
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(findWindow(t, snap, 300).EvidenceRefs); got != MaxEvidenceRefs {
		t.Fatalf("refs=%d", got)
	}
}

func TestSourceCapacityFailsClosed(t *testing.T) {
	a, _ := NewAccumulator(32, 1)
	if _, err := a.Observe(obs("a", "src-1", "h1", "g1", 80, 1000), 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Observe(obs("b", "src-2", "h2", "g2", 81, 1000), 1001); err == nil || err.Error() != "SOURCE_CAPACITY" {
		t.Fatalf("source capacity did not fail closed: %v", err)
	}
}

func TestObservationCapacityFailsClosed(t *testing.T) {
	a, _ := NewAccumulator(1, 8)
	if _, err := a.Observe(obs("a", "src-1", "h1", "g1", 80, 1000), 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Observe(obs("b", "src-1", "h2", "g2", 81, 1000), 1001); err == nil || err.Error() != "OBSERVATION_CAPACITY" {
		t.Fatalf("observation capacity did not fail closed: %v", err)
	}
}

func TestStaleAndFutureRejected(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	if _, err := a.Observe(obs("old", "src-1", "h1", "g1", 80, 1000), 1000+MaxWindow+1); err == nil || err.Error() != "STALE_OR_FUTURE" {
		t.Fatalf("stale accepted: %v", err)
	}
	if _, err := a.Observe(obs("future", "src-1", "h1", "g1", 80, 1004), 1000); err == nil || err.Error() != "STALE_OR_FUTURE" {
		t.Fatalf("future accepted: %v", err)
	}
}

func TestConcurrentSyntheticObserveIsBounded(t *testing.T) {
	a, _ := NewAccumulator(256, 8)
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := a.Observe(obs(fmt.Sprintf("e-%03d", i), "src-1", fmt.Sprintf("h-%03d", i), "g", 80, 1000+float64(i%5)), 1005)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	health := a.Health()
	if health["observations"].(int) != 100 {
		t.Fatalf("observations=%v", health["observations"])
	}
	if health["authority"] != "NOT_GRANTED" || health["live_capture"] != "DISABLED" {
		t.Fatalf("health invariant broken: %+v", health)
	}
}

func TestHighCardinalityRemainsBounded(t *testing.T) {
	a, _ := NewAccumulator(256, 8)
	for i := 0; i < 256; i++ {
		_, err := a.Observe(obs(fmt.Sprintf("hc-%03d", i), "src-1", fmt.Sprintf("host-%03d", i), fmt.Sprintf("g-%03d", i), 80, 1000+float64(i%10)), 1010)
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if _, err := a.Observe(obs("overflow", "src-1", "overflow-host", "overflow-group", 80, 1010), 1010); err == nil || err.Error() != "OBSERVATION_CAPACITY" {
		t.Fatalf("capacity overflow not rejected: %v", err)
	}
	if got := a.Health()["observations"].(int); got != 256 {
		t.Fatalf("bounded state changed unexpectedly: %d", got)
	}
}

func TestExpiryReleasesCapacity(t *testing.T) {
	a, _ := NewAccumulator(1, 8)
	if _, err := a.Observe(obs("old", "src-1", "old-host", "g1", 80, 1000), 1000); err != nil {
		t.Fatal(err)
	}
	// The previous item is now outside the 24h horizon and must be removed before capacity checks.
	now := 1000 + MaxWindow + 1
	if _, err := a.Observe(obs("new", "src-1", "new-host", "g2", 81, now), now); err != nil {
		t.Fatalf("expired state did not release capacity: %v", err)
	}
}

func TestInvalidDependencyGroupRejected(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	o := obs("a", "src-1", "host-1", "bad group", 80, 1000)
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "INVALID_ID" {
		t.Fatalf("invalid dependency group accepted: %v", err)
	}
}

func TestICMPDoesNotInventPortCardinality(t *testing.T) {
	a, _ := NewAccumulator(32, 8)
	o := obs("a", "src-1", "host-1", "icmp", 0, 1000)
	o.Protocol = "ICMP"
	snap, err := a.Observe(o, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if findWindow(t, snap, 300).UniquePorts != 0 {
		t.Fatalf("ICMP invented port cardinality: %+v", findWindow(t, snap, 300))
	}
}
