package ndredge

import (
	"fmt"
	"testing"
)

func obs(id, source, target string, port int, ts float64) Observation {
	return Observation{
		EventID: id, TenantID: "tenant-1", SensorID: "sensor-1", Epoch: "epoch-1",
		SourceID: source, TargetID: target, DestinationPort: port, Protocol: "TCP",
		Outcome: "REFUSED", TimestampUnix: ts, TrustLevel: "SYNTHETIC",
		Authorization: "NOT_GRANTED", Mode: "SYNTHETIC",
	}
}

func TestSyntheticFeatureAggregation(t *testing.T) {
	a, err := NewAccumulator(300, 32, 8)
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	for i := 0; i < 4; i++ {
		snap, err = a.Observe(obs(fmt.Sprintf("ev-%d", i), "src-1", "host-1", 20+i, 1000+float64(i)), 1005)
		if err != nil {
			t.Fatal(err)
		}
	}
	if snap.ObservationCount != 4 || snap.UniqueTargets != 1 || snap.UniquePorts != 4 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if snap.Authorization != "NOT_GRANTED" || snap.Mode != "SYNTHETIC" {
		t.Fatal("authority/mode invariant broken")
	}
}

func TestReplayRejected(t *testing.T) {
	a, _ := NewAccumulator(300, 32, 8)
	o := obs("same", "src-1", "host-1", 80, 1000)
	if _, err := a.Observe(o, 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "REPLAY" {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestLiveInputDisabled(t *testing.T) {
	a, _ := NewAccumulator(300, 32, 8)
	o := obs("ev-1", "src-1", "host-1", 80, 1000)
	o.TrustLevel = "AUTHENTICATED"
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "LIVE_INPUT_DISABLED" {
		t.Fatalf("live input accepted: %v", err)
	}
}

func TestAuthorityForbidden(t *testing.T) {
	a, _ := NewAccumulator(300, 32, 8)
	o := obs("ev-1", "src-1", "host-1", 80, 1000)
	o.Authorization = "GRANTED"
	if _, err := a.Observe(o, 1001); err == nil || err.Error() != "AUTHORITY_FORBIDDEN" {
		t.Fatalf("authority accepted: %v", err)
	}
}

func TestSourceCapacityFailsClosed(t *testing.T) {
	a, _ := NewAccumulator(300, 32, 1)
	if _, err := a.Observe(obs("a", "src-1", "host-1", 80, 1000), 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Observe(obs("b", "src-2", "host-1", 80, 1000), 1001); err == nil || err.Error() != "SOURCE_CAPACITY" {
		t.Fatalf("capacity did not fail closed: %v", err)
	}
}

func TestObservationCapacityFailsClosed(t *testing.T) {
	a, _ := NewAccumulator(300, 1, 8)
	if _, err := a.Observe(obs("a", "src-1", "host-1", 80, 1000), 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Observe(obs("b", "src-1", "host-2", 81, 1000), 1001); err == nil || err.Error() != "OBSERVATION_CAPACITY" {
		t.Fatalf("capacity did not fail closed: %v", err)
	}
}

func TestLowAndSlowFeature(t *testing.T) {
	a, _ := NewAccumulator(600, 32, 8)
	if _, err := a.Observe(obs("a", "src-1", "host-1", 80, 1000), 1000); err != nil {
		t.Fatal(err)
	}
	snap, err := a.Observe(obs("b", "src-1", "host-2", 80, 1125), 1125)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.LowAndSlow || snap.SpanSeconds < 120 {
		t.Fatalf("low-and-slow not represented: %+v", snap)
	}
}

func TestEvidenceRefsBounded(t *testing.T) {
	a, _ := NewAccumulator(300, 32, 8)
	var snap Snapshot
	var err error
	for i := 0; i < 20; i++ {
		snap, err = a.Observe(obs(fmt.Sprintf("ev-%02d", i), "src-1", fmt.Sprintf("host-%d", i), 100+i, 1000+float64(i)), 1020)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(snap.EvidenceRefs) != MaxEvidenceRefs {
		t.Fatalf("refs=%d", len(snap.EvidenceRefs))
	}
}
