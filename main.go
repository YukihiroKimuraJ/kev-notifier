// kev-notifier fetches the CISA Known Exploited Vulnerabilities (KEV)
// catalog, diffs it against the previously seen CVE IDs, and posts any new
// entries to a Slack incoming webhook.
//
// CISA retired its RSS feeds on 2025-05-12, so polling the official JSON
// catalog is the supported way to track KEV additions programmatically.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultCatalogURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	maxCatalogBytes       = 16 << 20
	maxCatalogEntries     = 10_000
	maxCatalogFieldRunes  = 4_000
	maxCatalogRemovals    = 25
	maxCatalogShrinkPct   = 5
	maxNewVulnerabilities = 100
)

var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// maxVulnsPerMessage keeps each Slack message under the 50-blocks API limit
// (1 header block + 2 blocks per CVE).
const maxVulnsPerMessage = 20

type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CveID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

type slackMessage struct {
	Text   string           `json:"text"`
	Blocks []map[string]any `json:"blocks"`
}

func main() {
	var (
		catalogURL = flag.String("catalog-url", defaultCatalogURL, "URL of the KEV catalog JSON")
		statePath  = flag.String("state", "state/seen_cves.json", "path to the seen-CVE state file")
		dryRun     = flag.Bool("dry-run", false, "print new entries to stdout instead of posting to Slack")
	)
	flag.Parse()

	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if !*dryRun && webhookURL == "" {
		log.Fatal("SLACK_WEBHOOK_URL is not set (use -dry-run to run without Slack)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := run(ctx, *catalogURL, *statePath, webhookURL, *dryRun); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, catalogURL, statePath, webhookURL string, dryRun bool) error {
	catalog, err := fetchCatalog(ctx, catalogURL)
	if err != nil {
		return fmt.Errorf("fetch catalog: %w", err)
	}
	log.Printf("catalog %s: %d entries", catalog.CatalogVersion, len(catalog.Vulnerabilities))

	seen, exists, err := loadSeen(statePath)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}

	// First run: seed the state with the full catalog and stay quiet, so a
	// fresh install does not flood Slack with 1600+ historical entries.
	if !exists {
		if dryRun {
			log.Printf("dry-run: would seed %s with %d CVE IDs", statePath, len(catalog.Vulnerabilities))
			return nil
		}
		if err := saveSeen(statePath, catalog); err != nil {
			return fmt.Errorf("seed state: %w", err)
		}
		log.Printf("no state file found; seeded %s with %d CVE IDs (no notification sent)",
			statePath, len(catalog.Vulnerabilities))
		return nil
	}

	if err := validateCatalogAgainstState(catalog, seen); err != nil {
		return fmt.Errorf("validate catalog: %w", err)
	}

	newVulns := diffNew(catalog, seen)
	if len(newVulns) == 0 {
		log.Print("no new KEV entries")
		if dryRun {
			return nil
		}
		// Still rewrite the state so removed entries drop out of it.
		return saveSeen(statePath, catalog)
	}
	log.Printf("%d new KEV entries", len(newVulns))

	messages := buildMessages(newVulns, catalog)
	if dryRun {
		for _, msg := range messages {
			payload, err := json.MarshalIndent(msg, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(payload))
		}
		// Dry runs never touch the state, so they can be repeated freely.
		return nil
	}

	for _, msg := range messages {
		if err := postSlack(ctx, webhookURL, msg); err != nil {
			// Leave the state untouched so the next run retries the
			// notification instead of silently dropping it.
			return fmt.Errorf("post to Slack: %w", err)
		}
	}
	return saveSeen(statePath, catalog)
}

func fetchCatalog(ctx context.Context, url string) (*Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kev-notifier (+https://github.com/YukihiroKimuraJ/kev-notifier)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("unexpected status %s: %s", resp.Status, body)
	}

	limited := &io.LimitedReader{R: resp.Body, N: maxCatalogBytes + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxCatalogBytes {
		return nil, fmt.Errorf("catalog exceeds %d-byte limit", maxCatalogBytes)
	}

	var catalog Catalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, err
	}
	if err := validateCatalog(&catalog); err != nil {
		return nil, err
	}
	return &catalog, nil
}

func validateCatalog(catalog *Catalog) error {
	count := len(catalog.Vulnerabilities)
	if count == 0 {
		return fmt.Errorf("catalog contains no vulnerabilities; refusing to proceed")
	}
	if count > maxCatalogEntries {
		return fmt.Errorf("catalog contains %d vulnerabilities, limit is %d", count, maxCatalogEntries)
	}
	if catalog.Count != count {
		return fmt.Errorf("catalog count %d does not match %d decoded vulnerabilities", catalog.Count, count)
	}
	if err := validateCatalogField("catalogVersion", catalog.CatalogVersion); err != nil {
		return err
	}

	seen := make(map[string]struct{}, count)
	for i, v := range catalog.Vulnerabilities {
		if !cveIDPattern.MatchString(v.CveID) {
			return fmt.Errorf("vulnerability %d has invalid CVE ID %q", i, v.CveID)
		}
		if _, exists := seen[v.CveID]; exists {
			return fmt.Errorf("catalog contains duplicate CVE ID %s", v.CveID)
		}
		seen[v.CveID] = struct{}{}
		for name, value := range map[string]string{
			"vendorProject":     v.VendorProject,
			"product":           v.Product,
			"vulnerabilityName": v.VulnerabilityName,
			"shortDescription":  v.ShortDescription,
			"dueDate":           v.DueDate,
		} {
			if err := validateCatalogField(name, value); err != nil {
				return fmt.Errorf("%s: %w", v.CveID, err)
			}
		}
	}
	return nil
}

func validateCatalogField(name, value string) error {
	if len([]rune(value)) > maxCatalogFieldRunes {
		return fmt.Errorf("%s exceeds %d-rune limit", name, maxCatalogFieldRunes)
	}
	return nil
}

func validateCatalogAgainstState(catalog *Catalog, seen map[string]bool) error {
	if len(seen) > 0 && len(catalog.Vulnerabilities) < len(seen) {
		removed := len(seen) - len(catalog.Vulnerabilities)
		if removed > maxCatalogRemovals && removed*100 > len(seen)*maxCatalogShrinkPct {
			return fmt.Errorf("catalog shrank from %d to %d entries; preserving last-known-good state", len(seen), len(catalog.Vulnerabilities))
		}
	}
	newCount := len(diffNew(catalog, seen))
	if newCount > maxNewVulnerabilities {
		return fmt.Errorf("catalog contains %d new vulnerabilities, per-run limit is %d", newCount, maxNewVulnerabilities)
	}
	return nil
}

func loadSeen(path string) (seen map[string]bool, exists bool, err error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	seen = make(map[string]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	return seen, true, nil
}

// saveSeen writes the full current catalog's CVE IDs, replacing the previous
// state so that entries CISA removes from the KEV also drop out of the state.
func saveSeen(path string, catalog *Catalog) error {
	ids := make([]string, 0, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		ids = append(ids, v.CveID)
	}
	sort.Strings(ids)

	data, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func diffNew(catalog *Catalog, seen map[string]bool) []Vulnerability {
	var newVulns []Vulnerability
	for _, v := range catalog.Vulnerabilities {
		if !seen[v.CveID] {
			newVulns = append(newVulns, v)
		}
	}
	sort.Slice(newVulns, func(i, j int) bool { return newVulns[i].CveID < newVulns[j].CveID })
	return newVulns
}

func buildMessages(vulns []Vulnerability, catalog *Catalog) []slackMessage {
	var messages []slackMessage
	for start := 0; start < len(vulns); start += maxVulnsPerMessage {
		chunk := vulns[start:min(start+maxVulnsPerMessage, len(vulns))]

		blocks := []map[string]any{
			{
				"type": "header",
				"text": map[string]any{
					"type": "plain_text",
					"text": fmt.Sprintf("🚨 CISA KEV に %d 件追加されました", len(vulns)),
				},
			},
		}
		for _, v := range chunk {
			blocks = append(blocks,
				map[string]any{
					"type": "section",
					"text": map[string]any{"type": "plain_text", "text": formatVuln(v), "emoji": true},
				},
				map[string]any{"type": "divider"},
			)
		}
		blocks = append(blocks, map[string]any{
			"type": "context",
			"elements": []map[string]any{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("KEV catalog %s ・ <https://www.cisa.gov/known-exploited-vulnerabilities-catalog|カタログを見る>", escapeSlackText(catalog.CatalogVersion)),
				},
			},
		})

		messages = append(messages, slackMessage{
			Text:   fmt.Sprintf("CISA KEV に %d 件追加されました", len(vulns)),
			Blocks: blocks,
		})
	}
	return messages
}

func formatVuln(v Vulnerability) string {
	ransomware := "Unknown"
	if v.KnownRansomwareCampaignUse == "Known" {
		ransomware = "⚠️ Known"
	}
	return fmt.Sprintf(
		"%s — %s %s\n%s\n%s\n対応期限: %s ・ ランサムウェアでの悪用: %s\nNVD: https://nvd.nist.gov/vuln/detail/%s",
		v.CveID, v.VendorProject, v.Product,
		v.VulnerabilityName,
		truncate(v.ShortDescription, 280),
		v.DueDate, ransomware, url.PathEscape(v.CveID),
	)
}

func escapeSlackText(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(s)
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

func postSlack(ctx context.Context, webhookURL string, msg slackMessage) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, body)
	}
	return nil
}
