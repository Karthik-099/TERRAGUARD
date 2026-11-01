package stats

import (
	"fmt"
	"testing"
	"time"
)

func TestRecordClampsAndAggregates(t *testing.T) {
	s := New()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.Record(Hit{Session: "a", Surface: "web", Scans: 3, Files: 4, Resources: 12, Findings: 10, Rules: map[string]int{"TG-X": 2}})
	s.Record(Hit{Session: "b", Surface: "evil", Scans: 1_000_000, Fixes: -5})
	s.Begin()
	snap := s.Snapshot()
	if snap.Today.Scans != 503 || snap.Today.Files != 4 || snap.Total.Resources != 12 || snap.Today.Fixes != 0 || snap.Total.Findings != 10 {
		t.Fatalf("today=%+v", snap.Today)
	}
	if snap.BySurface["other"] != 500 || snap.BySurface["web"] != 3 || snap.ActiveNow != 2 || snap.Running != 1 {
		t.Fatalf("snap=%+v", snap)
	}
	if len(snap.Days) != 7 || snap.Days[6].Date != "2026-10-25" || snap.TopRules[0].ID != "TG-X" {
		t.Fatalf("days/top=%+v %+v", snap.Days, snap.TopRules)
	}
	now = now.Add(3 * time.Minute)
	if s.Snapshot().ActiveNow != 0 {
		t.Fatal("stale sessions must expire")
	}
}

func TestRecordStaysBoundedAndKeepsCountingKnownRules(t *testing.T) {
	s := New()
	s.Record(Hit{Rules: map[string]int{"TG-AWS-S3-001": 1}})
	for i := 0; i < 600; i++ {
		s.Record(Hit{Session: fmt.Sprint("s", i), Rules: map[string]int{fmt.Sprint("R", i): 1}})
	}
	for i := 0; i < maxSessions+50; i++ {
		s.Record(Hit{Session: fmt.Sprint("x", i)})
	}
	s.Record(Hit{Rules: map[string]int{"TG-AWS-S3-001": 1}})
	if len(s.rules) > 500 || len(s.sessions) > maxSessions {
		t.Fatalf("unbounded: %d rules, %d sessions", len(s.rules), len(s.sessions))
	}
	if s.rules["TG-AWS-S3-001"] != 2 {
		t.Fatalf("known rule stopped counting once the table was full: %d", s.rules["TG-AWS-S3-001"])
	}
}
