package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
)

const MaxEncodedBytes = 64 * 1024
const MaxEvidenceRefs = 16

var identRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)
var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

var allowedLanguages = map[string]bool{
	"rust": true, "go": true, "c": true, "cpp": true,
	"csharp": true, "python": true, "typescript": true, "powershell": true,
}

// Envelope is telemetry/evidence metadata only. It can never confer response authority.
type Envelope struct {
	SchemaVersion    string   `json:"schema_version"`
	EventID          string   `json:"event_id"`
	TenantID         string   `json:"tenant_id"`
	ProducerID       string   `json:"producer_id"`
	ProducerLanguage string   `json:"producer_language"`
	TimestampUnix    float64  `json:"timestamp_unix"`
	TrustLevel       string   `json:"trust_level"`
	PayloadDigest    string   `json:"payload_digest"`
	EvidenceRefs     []string `json:"evidence_refs"`
	Authorization    string   `json:"authorization"`
	Mode             string   `json:"mode"`
}

func validID(s string) bool { return identRE.MatchString(s) }

func (e Envelope) Validate() error {
	if e.SchemaVersion != "cd.evidence-envelope.v1" {
		return errors.New("SCHEMA_VERSION")
	}
	for _, s := range []string{e.EventID, e.TenantID, e.ProducerID} {
		if !validID(s) {
			return errors.New("INVALID_ID")
		}
	}
	if !allowedLanguages[strings.ToLower(e.ProducerLanguage)] {
		return errors.New("PRODUCER_LANGUAGE")
	}
	if math.IsNaN(e.TimestampUnix) || math.IsInf(e.TimestampUnix, 0) || e.TimestampUnix <= 0 {
		return errors.New("TIMESTAMP")
	}
	if e.TrustLevel != "SYNTHETIC" && e.TrustLevel != "AUTHENTICATED" && e.TrustLevel != "UNTRUSTED" {
		return errors.New("TRUST_LEVEL")
	}
	if !hex64RE.MatchString(e.PayloadDigest) {
		return errors.New("PAYLOAD_DIGEST")
	}
	if len(e.EvidenceRefs) == 0 || len(e.EvidenceRefs) > MaxEvidenceRefs {
		return errors.New("EVIDENCE_BOUND")
	}
	seen := make(map[string]struct{}, len(e.EvidenceRefs))
	for _, r := range e.EvidenceRefs {
		if !validID(r) {
			return errors.New("EVIDENCE_ID")
		}
		if _, ok := seen[r]; ok {
			return errors.New("EVIDENCE_DUPLICATE")
		}
		seen[r] = struct{}{}
	}
	if e.Authorization != "NOT_GRANTED" {
		return errors.New("AUTHORITY_FORBIDDEN")
	}
	if e.Mode != "OBSERVE" && e.Mode != "SYNTHETIC" {
		return errors.New("MODE")
	}
	return nil
}

func DecodeStrict(raw []byte) (Envelope, error) {
	var zero Envelope
	if len(raw) == 0 || len(raw) > MaxEncodedBytes {
		return zero, errors.New("ENCODED_BOUND")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e Envelope
	if err := dec.Decode(&e); err != nil {
		return zero, fmt.Errorf("DECODE: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return zero, errors.New("TRAILING_DATA")
	}
	if err := e.Validate(); err != nil {
		return zero, err
	}
	return e, nil
}
