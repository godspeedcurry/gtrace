//go:build windows

package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gtrace/pkg/model"

	_ "modernc.org/sqlite" // Register sqlite driver
)

// CollectBrowserHistory scans Chrome and Edge History files using SQL.
func CollectBrowserHistory(ctx context.Context, callback func(model.TimelineEvent)) error {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return nil
	}

	targets := map[string]string{
		"Chrome": filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History"),
		"Edge":   filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History"),
	}

	for browser, path := range targets {
		if _, err := os.Stat(path); err == nil {
			if err := queryHistoryDB(ctx, browser, path, callback); err != nil {
				fmt.Printf("Error querying %s: %v\n", browser, err)
			}
		}
	}

	return nil
}

func queryHistoryDB(ctx context.Context, browser, path string, callback func(model.TimelineEvent)) error {
	// 1. Create a Temp Copy to bypass lock
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, fmt.Sprintf("gtrace_hist_%d.tmp", time.Now().UnixNano()))

	if err := copyLockedFile(path, tempFile); err != nil {
		return err
	}
	defer os.Remove(tempFile)

	// 2. Open SQLite Database
	db, err := sql.Open("sqlite", tempFile)
	if err != nil {
		return fmt.Errorf("failed to open sqlite DB: %w", err)
	}
	defer db.Close()

	// 3. Query
	// WebKit timestamps are microseconds since 1601-01-01 (Windows Epoch)
	rows, err := db.QueryContext(ctx, `
		SELECT url, title, last_visit_time 
		FROM urls 
		ORDER BY last_visit_time DESC 
		LIMIT 1000
	`)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var (
		urlStr    string
		title     string
		visitTime int64
	)

	for rows.Next() {
		if err := rows.Scan(&urlStr, &title, &visitTime); err != nil {
			continue
		}

		// Convert Timestamp (WebKit/Chrome Epoch: Microseconds since 1601-01-01)
		// To avoid overflow in Go's time.Duration (which is nanoseconds and maxes at ~290 years),
		// we subtract the Unix Epoch offset in seconds first.
		// Offset from 1601 to 1970 is 11,644,473,600 seconds.
		const unixEpochOffset = 11644473600

		s := (visitTime / 1000000) - unixEpochOffset
		ns := (visitTime % 1000000) * 1000
		ts := time.Unix(s, ns).UTC()

		// Smart logic: Extract hostname as Subject for better scannability
		displaySubject := urlStr
		if u, err := url.Parse(urlStr); err == nil {
			displaySubject = u.Host
		}

		callback(model.TimelineEvent{
			EventTime: ts,
			Source:    "Browser",
			Artifact:  browser + " History",
			Action:    "Page Visit",
			Subject:   displaySubject,
			Details: map[string]string{
				"URL":     urlStr,
				"Title":   title,
				"EventID": "URL", // Virtual ID for UI
			},
			EvidenceRef: model.EvidenceRef{
				SourcePath: path,
			},
		})
	}

	return nil
}
