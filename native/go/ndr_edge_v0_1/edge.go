package ndredge

import (
	"errors"
	"math"
	"regexp"
	"sort"
	"sync"
)

const (
	MaxObservations  = 512
	MaxSources       = 64
	MaxEvidenceRefs  = 16
	MaxWindowSeconds = 86400
)

var idRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)

// Observation is structured metadata only. v0.1 intentionally has no live packet capture.
type Observation struct {
	EventID         string
	TenantID        string
	SensorID        string
	Epoch           string
	SourceID        string
	TargetID        string
	DestinationPort int
	Protocol        string
	Outcome         string
	TimestampUnix   float64
	TrustLevel      string
	Authorization   string
	Mode            string
}

// Snapshot is a bounded feature view. It is not a detection, risk score, or authorization.
type Snapshot struct {
	TenantID         string
	SensorID         string
	Epoch            string
	SourceID         string
	ObservationCount int
	UniqueTargets    int
	UniquePorts      int
	FailureRatio     float64
	SpanSeconds      float64
	Burst10sCount    int
	LowAndSlow       bool
	EvidenceRefs     []string
	Authorization    string
	Mode             string
}

type Accumulator struct {
	mu           sync.Mutex
	window       float64
	maxObs       int
	maxSources   int
	observations []Observation
	seen         map[string]struct{}
}

func NewAccumulator(windowSeconds float64, maxObservations, maxSources int) (*Accumulator, error) {
	if math.IsNaN(windowSeconds) || math.IsInf(windowSeconds, 0) || windowSeconds <= 0 || windowSeconds > MaxWindowSeconds {
		return nil, errors.New("WINDOW_BOUND")
	}
	if maxObservations < 1 || maxObservations > MaxObservations {
		return nil, errors.New("OBSERVATION_BOUND")
	}
	if maxSources < 1 || maxSources > MaxSources {
		return nil, errors.New("SOURCE_BOUND")
	}
	return &Accumulator{
		window:     windowSeconds,
		maxObs:     maxObservations,
		maxSources: maxSources,
		seen:       make(map[string]struct{}, maxObservations),
	}, nil
}

func validate(o Observation) error {
	for _, value := range []string{o.EventID, o.TenantID, o.SensorID, o.Epoch, o.SourceID, o.TargetID} {
		if !idRE.MatchString(value) {
			return errors.New("INVALID_ID")
		}
	}
	if math.IsNaN(o.TimestampUnix) || math.IsInf(o.TimestampUnix, 0) || o.TimestampUnix <= 0 {
		return errors.New("TIMESTAMP")
	}
	if o.DestinationPort < 0 || o.DestinationPort > 65535 {
		return errors.New("PORT")
	}
	if o.Protocol != "TCP" && o.Protocol != "UDP" && o.Protocol != "ICMP" {
		return errors.New("PROTOCOL")
	}
	if o.Outcome != "SUCCESS" && o.Outcome != "REFUSED" && o.Outcome != "TIMEOUT" && o.Outcome != "UNKNOWN" {
		return errors.New("OUTCOME")
	}
	if o.TrustLevel != "SYNTHETIC" {
		return errors.New("LIVE_INPUT_DISABLED")
	}
	if o.Authorization != "NOT_GRANTED" {
		return errors.New("AUTHORITY_FORBIDDEN")
	}
	if o.Mode != "SYNTHETIC" {
		return errors.New("MODE")
	}
	return nil
}

func identity(o Observation) string {
	return o.TenantID + "|" + o.SensorID + "|" + o.Epoch + "|" + o.EventID
}

// Observe accepts only synthetic structured metadata and returns a non-authoritative feature snapshot.
func (a *Accumulator) Observe(o Observation, now float64) (Snapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var zero Snapshot
	if err := validate(o); err != nil {
		return zero, err
	}
	if math.IsNaN(now) || math.IsInf(now, 0) || now <= 0 || o.TimestampUnix > now+2 || o.TimestampUnix < now-a.window {
		return zero, errors.New("STALE_OR_FUTURE")
	}
	id := identity(o)
	if _, ok := a.seen[id]; ok {
		return zero, errors.New("REPLAY")
	}

	// Remove expired observations before enforcing bounds. Seen identities remain only for the active window.
	kept := a.observations[:0]
	newSeen := make(map[string]struct{}, len(a.observations)+1)
	for _, item := range a.observations {
		if item.TimestampUnix >= now-a.window {
			kept = append(kept, item)
			newSeen[identity(item)] = struct{}{}
		}
	}
	a.observations = kept
	a.seen = newSeen
	if _, ok := a.seen[id]; ok {
		return zero, errors.New("REPLAY")
	}

	sources := map[string]struct{}{}
	for _, item := range a.observations {
		sources[item.SourceID] = struct{}{}
	}
	if _, exists := sources[o.SourceID]; !exists && len(sources) >= a.maxSources {
		return zero, errors.New("SOURCE_CAPACITY")
	}
	if len(a.observations) >= a.maxObs {
		return zero, errors.New("OBSERVATION_CAPACITY")
	}

	a.observations = append(a.observations, o)
	a.seen[id] = struct{}{}
	return a.snapshotFor(o, now), nil
}

func (a *Accumulator) snapshotFor(current Observation, now float64) Snapshot {
	items := make([]Observation, 0, len(a.observations))
	for _, item := range a.observations {
		if item.TenantID == current.TenantID && item.SensorID == current.SensorID && item.Epoch == current.Epoch && item.SourceID == current.SourceID {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].TimestampUnix < items[j].TimestampUnix })
	targets := map[string]struct{}{}
	ports := map[int]struct{}{}
	failures := 0
	burst := 0
	refs := make([]string, 0, MaxEvidenceRefs)
	for _, item := range items {
		targets[item.TargetID] = struct{}{}
		if item.Protocol != "ICMP" {
			ports[item.DestinationPort] = struct{}{}
		}
		if item.Outcome == "REFUSED" || item.Outcome == "TIMEOUT" {
			failures++
		}
		if item.TimestampUnix >= now-10 {
			burst++
		}
	}
	start := 0
	if len(items) > MaxEvidenceRefs {
		start = len(items) - MaxEvidenceRefs
	}
	for _, item := range items[start:] {
		refs = append(refs, item.EventID)
	}
	span := 0.0
	if len(items) > 1 {
		span = items[len(items)-1].TimestampUnix - items[0].TimestampUnix
	}
	failureRatio := 0.0
	if len(items) > 0 {
		failureRatio = float64(failures) / float64(len(items))
	}
	return Snapshot{
		TenantID:         current.TenantID,
		SensorID:         current.SensorID,
		Epoch:            current.Epoch,
		SourceID:         current.SourceID,
		ObservationCount: len(items),
		UniqueTargets:    len(targets),
		UniquePorts:      len(ports),
		FailureRatio:     failureRatio,
		SpanSeconds:      span,
		Burst10sCount:    burst,
		LowAndSlow:       span >= 120,
		EvidenceRefs:     refs,
		Authorization:    "NOT_GRANTED",
		Mode:             "SYNTHETIC",
	}
}

func (a *Accumulator) Health() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	sources := map[string]struct{}{}
	for _, item := range a.observations {
		sources[item.SourceID] = struct{}{}
	}
	return map[string]any{
		"mode":                 "SYNTHETIC",
		"authority":            "NOT_GRANTED",
		"observations":         len(a.observations),
		"sources":              len(sources),
		"observation_capacity": a.maxObs,
		"source_capacity":      a.maxSources,
	}
}
