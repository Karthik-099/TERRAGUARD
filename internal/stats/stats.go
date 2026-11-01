// Package stats: anonymous counters (numbers only), same JSON as stats-worker.
package stats

import (
	"sort"
	"sync"
	"time"
)

type Counters struct {
	Scans     int `json:"scans"`     // evaluations run
	Files     int `json:"files"`     // .tf/.tfvars files evaluated
	Resources int `json:"resources"` // resources analyzed
	Fixes     int `json:"fixes"`
	AI        int `json:"ai"`
	Findings  int `json:"findings"`
	MsTotal   int `json:"ms_total"`
}

// Hit is what clients report; every field is a count.
type Hit struct {
	Session   string         `json:"session"`
	Surface   string         `json:"surface"`
	Scans     int            `json:"scans"`
	Files     int            `json:"files"`
	Resources int            `json:"resources"`
	Fixes     int            `json:"fixes"`
	AI        int            `json:"ai"`
	Findings  int            `json:"findings"`
	Ms        int            `json:"ms"`
	Rules     map[string]int `json:"rules"`
}

type Store struct {
	mu        sync.Mutex
	days      map[string]*Counters
	total     Counters
	surfaces  map[string]int
	rules     map[string]int
	sessions  map[string]time.Time
	running   int
	startedAt time.Time
	now       func() time.Time
}

// In memory only: counters reset on restart.
func New() *Store {
	return &Store{days: map[string]*Counters{}, surfaces: map[string]int{}, rules: map[string]int{},
		sessions: map[string]time.Time{}, startedAt: time.Now(), now: time.Now}
}

func clamp(n, max int) int {
	if n < 0 {
		return 0
	}
	if n > max {
		return max
	}
	return n
}

func (s *Store) Record(h Hit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Clients are untrusted: cap every field so one caller can't skew the dashboard.
	c := Counters{Scans: clamp(h.Scans, 500), Files: clamp(h.Files, 20000), Resources: clamp(h.Resources, 100000), Fixes: clamp(h.Fixes, 500), AI: clamp(h.AI, 100), Findings: clamp(h.Findings, 50000), MsTotal: clamp(h.Ms, 600000)}
	day := s.now().UTC().Format("2006-01-02")
	d := s.days[day]
	if d == nil {
		d = &Counters{}
		s.days[day] = d
	}
	for _, x := range []*Counters{d, &s.total} {
		x.Scans += c.Scans
		x.Files += c.Files
		x.Resources += c.Resources
		x.Fixes += c.Fixes
		x.AI += c.AI
		x.Findings += c.Findings
		x.MsTotal += c.MsTotal
	}
	surface := h.Surface
	if surface != "web" && surface != "cli" && surface != "action" && surface != "api" && surface != "mcp" {
		surface = "other"
	}
	s.surfaces[surface] += c.Scans
	for id, n := range h.Rules {
		if _, known := s.rules[id]; known || (len(id) <= 40 && len(s.rules) < 500) {
			s.rules[id] += clamp(n, 1000)
		}
	}
	if h.Session != "" && len(h.Session) <= 64 {
		if len(s.sessions) >= maxSessions {
			s.pruneSessions(s.now())
		}
		if len(s.sessions) < maxSessions {
			s.sessions[h.Session] = s.now()
		}
	}
}

// maxSessions bounds memory when untrusted clients send many session IDs.
const maxSessions = 10000

// pruneSessions forgets sessions idle for more than two minutes.
func (s *Store) pruneSessions(now time.Time) {
	for id, t := range s.sessions {
		if now.Sub(t) > 2*time.Minute {
			delete(s.sessions, id)
		}
	}
}

// Begin/End track requests currently executing on this server.
func (s *Store) Begin() { s.mu.Lock(); s.running++; s.mu.Unlock() }
func (s *Store) End()   { s.mu.Lock(); s.running--; s.mu.Unlock() }

type Day struct {
	Date string `json:"date"`
	Counters
}

type Snapshot struct {
	Source    string         `json:"source"`
	Today     Counters       `json:"today"`
	Total     Counters       `json:"total"`
	Days      []Day          `json:"days"`
	ActiveNow int            `json:"active_now"`
	Running   int            `json:"running_now"`
	BySurface map[string]int `json:"by_surface"`
	TopRules  []RuleCount    `json:"top_rules"`
	Since     time.Time      `json:"since"`
	Updated   time.Time      `json:"updated"`
}

type RuleCount struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	snap := Snapshot{Source: "server", Total: s.total, Running: s.running, BySurface: map[string]int{}, Since: s.startedAt, Updated: now}
	for k, v := range s.surfaces {
		snap.BySurface[k] = v
	}
	for i := 6; i >= 0; i-- {
		date := now.UTC().AddDate(0, 0, -i).Format("2006-01-02")
		d := Day{Date: date}
		if c := s.days[date]; c != nil {
			d.Counters = *c
		}
		snap.Days = append(snap.Days, d)
	}
	snap.Today = snap.Days[len(snap.Days)-1].Counters
	s.pruneSessions(now)
	snap.ActiveNow = len(s.sessions)
	for id, n := range s.rules {
		snap.TopRules = append(snap.TopRules, RuleCount{id, n})
	}
	sort.Slice(snap.TopRules, func(i, j int) bool {
		if snap.TopRules[i].Count != snap.TopRules[j].Count {
			return snap.TopRules[i].Count > snap.TopRules[j].Count
		}
		return snap.TopRules[i].ID < snap.TopRules[j].ID
	})
	if len(snap.TopRules) > 10 {
		snap.TopRules = snap.TopRules[:10]
	}
	return snap
}
