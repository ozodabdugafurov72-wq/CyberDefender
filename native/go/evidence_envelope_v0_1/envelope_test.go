package envelope

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func valid() Envelope {
	return Envelope{
		SchemaVersion: "cd.evidence-envelope.v1", EventID: "evt-1", TenantID: "tenant-1",
		ProducerID: "edge-1", ProducerLanguage: "go", TimestampUnix: 1789400000,
		TrustLevel: "SYNTHETIC", PayloadDigest: strings.Repeat("a", 64),
		EvidenceRefs: []string{"ev-1"}, Authorization: "NOT_GRANTED", Mode: "SYNTHETIC",
	}
}

func TestValid(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestAuthorityForbidden(t *testing.T) {
	e := valid()
	e.Authorization = "GRANTED"
	if e.Validate() == nil {
		t.Fatal("authority accepted")
	}
}
func TestDuplicateEvidence(t *testing.T) {
	e := valid()
	e.EvidenceRefs = []string{"ev-1", "ev-1"}
	if e.Validate() == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestNaNTime(t *testing.T) {
	e := valid()
	e.TimestampUnix = math.NaN()
	if e.Validate() == nil {
		t.Fatal("NaN accepted")
	}
}
func TestUnknownLanguage(t *testing.T) {
	e := valid()
	e.ProducerLanguage = "magic"
	if e.Validate() == nil {
		t.Fatal("language accepted")
	}
}
func TestStrictUnknownField(t *testing.T) {
	e := valid()
	b, _ := json.Marshal(e)
	b = append(b[:len(b)-1], []byte(`,"danger":"execute"}`)...)
	if _, err := DecodeStrict(b); err == nil {
		t.Fatal("unknown field accepted")
	}
}
func TestTrailingData(t *testing.T) {
	b, _ := json.Marshal(valid())
	b = append(b, []byte(` {}`)...)
	if _, err := DecodeStrict(b); err == nil {
		t.Fatal("trailing data accepted")
	}
}
func TestOversize(t *testing.T) {
	if _, err := DecodeStrict(make([]byte, MaxEncodedBytes+1)); err == nil {
		t.Fatal("oversize accepted")
	}
}
