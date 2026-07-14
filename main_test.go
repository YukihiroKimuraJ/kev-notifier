package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeCatalog(ids ...string) *Catalog {
	c := &Catalog{CatalogVersion: "test", Count: len(ids)}
	for _, id := range ids {
		c.Vulnerabilities = append(c.Vulnerabilities, Vulnerability{
			CveID:             id,
			VendorProject:     "Vendor",
			Product:           "Product",
			VulnerabilityName: "Test Vulnerability",
			DueDate:           "2026-08-01",
		})
	}
	return c
}

func TestDiffNew(t *testing.T) {
	catalog := makeCatalog("CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0003")
	seen := map[string]bool{"CVE-2026-0001": true, "CVE-2026-0003": true}

	got := diffNew(catalog, seen)
	if len(got) != 1 || got[0].CveID != "CVE-2026-0002" {
		t.Fatalf("diffNew = %v, want [CVE-2026-0002]", got)
	}

	if got := diffNew(catalog, map[string]bool{
		"CVE-2026-0001": true, "CVE-2026-0002": true, "CVE-2026-0003": true,
	}); len(got) != 0 {
		t.Fatalf("diffNew with all seen = %v, want empty", got)
	}
}

func TestDiffNewSortsByCveID(t *testing.T) {
	catalog := makeCatalog("CVE-2026-0300", "CVE-2026-0100", "CVE-2026-0200")
	got := diffNew(catalog, map[string]bool{})
	want := []string{"CVE-2026-0100", "CVE-2026-0200", "CVE-2026-0300"}
	for i, v := range got {
		if v.CveID != want[i] {
			t.Fatalf("diffNew order = %v, want %v", got, want)
		}
	}
}

func TestSeenStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "seen.json")

	if _, exists, err := loadSeen(path); err != nil || exists {
		t.Fatalf("loadSeen on missing file: exists=%v err=%v, want false nil", exists, err)
	}

	catalog := makeCatalog("CVE-2026-0002", "CVE-2026-0001")
	if err := saveSeen(path, catalog); err != nil {
		t.Fatal(err)
	}

	seen, exists, err := loadSeen(path)
	if err != nil || !exists {
		t.Fatalf("loadSeen after save: exists=%v err=%v", exists, err)
	}
	if len(seen) != 2 || !seen["CVE-2026-0001"] || !seen["CVE-2026-0002"] {
		t.Fatalf("seen = %v, want both CVE IDs", seen)
	}

	// State is fully replaced, so entries removed from the catalog disappear.
	if err := saveSeen(path, makeCatalog("CVE-2026-0001")); err != nil {
		t.Fatal(err)
	}
	seen, _, _ = loadSeen(path)
	if len(seen) != 1 || seen["CVE-2026-0002"] {
		t.Fatalf("seen after removal = %v, want only CVE-2026-0001", seen)
	}
}

func TestBuildMessagesChunking(t *testing.T) {
	ids := make([]string, 45)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2026-%04d", i)
	}
	catalog := makeCatalog(ids...)

	messages := buildMessages(catalog.Vulnerabilities, catalog)
	if len(messages) != 3 {
		t.Fatalf("got %d messages for 45 vulns, want 3", len(messages))
	}
	for i, msg := range messages {
		if n := len(msg.Blocks); n > 50 {
			t.Fatalf("message %d has %d blocks, exceeds Slack's 50-block limit", i, n)
		}
	}
}

func TestFormatVulnRansomwareFlag(t *testing.T) {
	v := makeCatalog("CVE-2026-0001").Vulnerabilities[0]

	if got := formatVuln(v); strings.Contains(got, "⚠️") {
		t.Fatalf("unexpected ransomware warning for Unknown: %s", got)
	}
	v.KnownRansomwareCampaignUse = "Known"
	if got := formatVuln(v); !strings.Contains(got, "⚠️ *Known*") {
		t.Fatalf("missing ransomware warning for Known: %s", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Fatalf("truncate(short) = %q", got)
	}
	// Multibyte text must be cut on rune boundaries, not bytes.
	if got := truncate("あいうえお", 3); got != "あいう…" {
		t.Fatalf("truncate(あいうえお, 3) = %q, want あいう…", got)
	}
}

// TestRunEndToEnd drives run() against fake CISA and Slack servers:
// first run seeds silently, second run notifies only the new entry.
func TestRunEndToEnd(t *testing.T) {
	catalog := makeCatalog("CVE-2026-0001", "CVE-2026-0002")
	cisa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(catalog)
	}))
	defer cisa.Close()

	var posts []slackMessage
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg slackMessage
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			t.Errorf("bad webhook payload: %v", err)
		}
		posts = append(posts, msg)
	}))
	defer slack.Close()

	statePath := filepath.Join(t.TempDir(), "seen.json")
	ctx := context.Background()

	// First run: seed only, no notification.
	if err := run(ctx, cisa.URL, statePath, slack.URL, false); err != nil {
		t.Fatal(err)
	}
	if len(posts) != 0 {
		t.Fatalf("seed run posted %d messages, want 0", len(posts))
	}

	// Second run with one added CVE: exactly one notification.
	catalog.Vulnerabilities = append(catalog.Vulnerabilities,
		Vulnerability{CveID: "CVE-2026-0003", VendorProject: "V", Product: "P"})
	if err := run(ctx, cisa.URL, statePath, slack.URL, false); err != nil {
		t.Fatal(err)
	}
	if len(posts) != 1 {
		t.Fatalf("got %d messages, want 1", len(posts))
	}
	if !strings.Contains(posts[0].Text, "1 件") {
		t.Fatalf("message text = %q, want mention of 1 new entry", posts[0].Text)
	}

	// Third run with no changes: quiet.
	if err := run(ctx, cisa.URL, statePath, slack.URL, false); err != nil {
		t.Fatal(err)
	}
	if len(posts) != 1 {
		t.Fatalf("no-change run posted extra messages: %d total", len(posts))
	}
}

// TestRunDryRunNeverWritesState ensures dry runs can be repeated freely.
func TestRunDryRunNeverWritesState(t *testing.T) {
	catalog := makeCatalog("CVE-2026-0001")
	cisa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(catalog)
	}))
	defer cisa.Close()

	statePath := filepath.Join(t.TempDir(), "seen.json")
	ctx := context.Background()

	// Dry run before any state exists: no seeding either.
	if err := run(ctx, cisa.URL, statePath, "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("dry run created a state file")
	}

	// Seed for real, add a CVE, then dry run: state must stay as seeded.
	if err := run(ctx, cisa.URL, statePath, "", false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(statePath)
	catalog.Vulnerabilities = append(catalog.Vulnerabilities,
		Vulnerability{CveID: "CVE-2026-0002", VendorProject: "V", Product: "P"})
	if err := run(ctx, cisa.URL, statePath, "", true); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(statePath)
	if string(before) != string(after) {
		t.Fatal("dry run modified the state file")
	}
}

// TestRunKeepsStateOnSlackFailure ensures a failed webhook call leaves the
// state untouched so the notification is retried on the next run.
func TestRunKeepsStateOnSlackFailure(t *testing.T) {
	catalog := makeCatalog("CVE-2026-0001")
	cisa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(catalog)
	}))
	defer cisa.Close()

	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no_service", http.StatusServiceUnavailable)
	}))
	defer slack.Close()

	statePath := filepath.Join(t.TempDir(), "seen.json")
	ctx := context.Background()

	if err := run(ctx, cisa.URL, statePath, slack.URL, false); err != nil {
		t.Fatal(err) // seed run never touches Slack
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	catalog.Vulnerabilities = append(catalog.Vulnerabilities,
		Vulnerability{CveID: "CVE-2026-0002", VendorProject: "V", Product: "P"})
	if err := run(ctx, cisa.URL, statePath, slack.URL, false); err == nil {
		t.Fatal("run succeeded despite Slack failure, want error")
	}

	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("state was updated even though the Slack post failed")
	}
}
