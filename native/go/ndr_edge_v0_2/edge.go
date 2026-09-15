package ndredgev02

import (
	"errors"
	"math"
	"regexp"
	"sort"
	"sync"
)

const (
	MaxObservations = 2048
	MaxSources      = 128
	MaxEvidenceRefs = 24
	MaxWindow       = 86400.0
)

var (
	idRE          = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)
	WindowSeconds = []int{5, 30, 300, 3600, 21600, 86400}
)

// Observation is structured synthetic metadata only. v0.2 has no live packet capture.
type Observation struct {
	EventID         string
	TenantID        string
	SensorID        string
	Epoch           string
	SourceID        string
	TargetID        string
	DependencyGroup string
	DestinationPort int
	Protocol        string
	Outcome         string
	TimestampUnix   float64
	TrustLevel      string
	Authorization   string
	Mode            string
}

// WindowSnapshot is a bounded, non-authoritative feature view for one time window.
type WindowSnapshot struct {
	WindowSeconds    int
	ObservationCount int
	UniqueTargets    int
	UniquePorts      int
	DependencyGroups int
	FailureRatio     float64
	SpanSeconds      float64
	Burst5sCount     int
	LowAndSlow       bool
	EvidenceRefs     []string
	Authorization    string
	Mode             string
}

// MultiWindowSnapshot is not a detection, risk score, probability, or authorization.
type MultiWindowSnapshot struct {
	TenantID        string
	SensorID        string
	Epoch           string
	SourceID        string
	Windows         []WindowSnapshot
	LongHorizonOnly bool
	Authorization   string
	Mode            string
}

type Accumulator struct {
	mu           sync.Mutex
	maxObs       int
	maxSources   int
	observations []Observation
	seen         map[string]struct{}
}

func NewAccumulator(maxObservations, maxSources int) (*Accumulator, error) {
	if maxObservations < 1 || maxObservations > MaxObservations {
		return nil, errors.New("OBSERVATION_BOUND")
	}
	if maxSources < 1 || maxSources > MaxSources {
		return nil, errors.New("SOURCE_BOUND")
	}
	return &Accumulator{
		maxObs:     maxObservations,
		maxSources: maxSources,
		seen:       make(map[string]struct{}, maxObservations),
	}, nil
}

func validate(o Observation) error {
	for _, value := range []string{
		o.EventID,
		o.TenantID,
		o.SensorID,
		o.Epoch,
		o.SourceID,
		o.TargetID,
		o.DependencyGroup,
	} {
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

// Observe accepts only synthetic structured metadata and returns a multi-window feature snapshot.
func (a *Accumulator) Observe(o Observation, now float64) (MultiWindowSnapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var zero MultiWindowSnapshot
	if err := validate(o); err != nil {
		return zero, err
	}
	if math.IsNaN(now) || math.IsInf(now, 0) || now <= 0 || o.TimestampUnix > now+2 || o.TimestampUnix < now-MaxWindow {
		return zero, errors.New("STALE_OR_FUTURE")
	}
	id := identity(o)
	if _, ok := a.seen[id]; ok {
		return zero, errors.New("REPLAY")
	}

	kept := a.observations[:0]
	newSeen := make(map[string]struct{}, len(a.observations)+1)
	for _, item := range a.observations {
		if item.TimestampUnix >= now-MaxWindow {
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

func (a *Accumulator) snapshotFor(current Observation, now float64) MultiWindowSnapshot {
	items := make([]Observation, 0, len(a.observations))
	for _, item := range a.observations {
		if item.TenantID == current.TenantID &&
			item.SensorID == current.SensorID &&
			item.Epoch == current.Epoch &&
			item.SourceID == current.SourceID {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].TimestampUnix < items[j].TimestampUnix })

	windows := make([]WindowSnapshot, 0, len(WindowSeconds))
	for _, seconds := range WindowSeconds {
		windows = append(windows, buildWindow(items, now, seconds))
	}

	shortCount := 0
	longCount := 0
	for _, item := range windows {
		if item.WindowSeconds == 30 {
			shortCount = item.ObservationCount
		}
		if item.WindowSeconds == 3600 {
			longCount = item.ObservationCount
		}
	}

	return MultiWindowSnapshot{
		TenantID:        current.TenantID,
		SensorID:        current.SensorID,
		Epoch:           current.Epoch,
		SourceID:        current.SourceID,
		Windows:         windows,
		LongHorizonOnly: longCount >= 3 && shortCount <= 1,
		Authorization:   "NOT_GRANTED",
		Mode:            "SYNTHETIC",
	}
}

func buildWindow(items []Observation, now float64, seconds int) WindowSnapshot {
	eligible := make([]Observation, 0, len(items))
	cutoff := now - float64(seconds)
	for _, item := range items {
		if item.TimestampUnix >= cutoff {
			eligible = append(eligible, item)
		}
	}

	targets := map[string]struct{}{}
	ports := map[int]struct{}{}
	groups := map[string]struct{}{}
	failures := 0
	burst := 0
	refs := make([]string, 0, MaxEvidenceRefs)
	for _, item := range eligible {
		targets[item.TargetID] = struct{}{}
		groups[item.DependencyGroup] = struct{}{}
		if item.Protocol != "ICMP" {
			ports[item.DestinationPort] = struct{}{}
		}
		if item.Outcome == "REFUSED" || item.Outcome == "TIMEOUT" {
			failures++
		}
		if item.TimestampUnix >= now-5 {
			burst++
		}
	}

	start := 0
	if len(eligible) > MaxEvidenceRefs {
		start = len(eligible) - MaxEvidenceRefs
	}
	for _, item := range eligible[start:] {
		refs = append(refs, item.EventID)
	}

	span := 0.0
	if len(eligible) > 1 {
		span = eligible[len(eligible)-1].TimestampUnix - eligible[0].TimestampUnix
	}
	failureRatio := 0.0
	if len(eligible) > 0 {
		failureRatio = float64(failures) / float64(len(eligible))
	}

	return WindowSnapshot{
		WindowSeconds:    seconds,
		ObservationCount: len(eligible),
		UniqueTargets:    len(targets),
		UniquePorts:      len(ports),
		DependencyGroups: len(groups),
		FailureRatio:     failureRatio,
		SpanSeconds:      span,
		Burst5sCount:     burst,
		LowAndSlow:       span >= 120 && burst <= 1,
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
		"live_capture":         "DISABLED",
		"observations":         len(a.observations),
		"sources":              len(sources),
		"observation_capacity": a.maxObs,
		"source_capacity":      a.maxSources,
		"window_count":         len(WindowSeconds),
	}
}
