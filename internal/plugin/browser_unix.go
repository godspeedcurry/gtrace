//go:build !windows

package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gtrace/pkg/model"

	_ "modernc.org/sqlite"
)

func CollectBrowserHistory(ctx context.Context, callback func(model.TimelineEvent)) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	targets := make(map[string]string)

	if runtime.GOOS == "darwin" {
		// macOS Paths
		targets["Chrome"] = filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default", "History")
		targets["Edge"] = filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "Default", "History")
		// Helper for Brave?
		targets["Brave"] = filepath.Join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "History")
	} else {
		// Linux Paths (Assumption)
		targets["Chrome"] = filepath.Join(home, ".config", "google-chrome", "Default", "History")
		targets["Edge"] = filepath.Join(home, ".config", "microsoft-edge", "Default", "History")
	}

	for browser, path := range targets {
		// Check existence
		if _, err := os.Stat(path); err == nil {
			if err := queryHistoryDB(ctx, browser, path, callback); err != nil {
				// Just log to stdout for now or ignore
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

	if err := copyFile(path, tempFile); err != nil {
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

	// Epoch start for WebKit (1601-01-01)
	webkitEpoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

	for rows.Next() {
		if err := rows.Scan(&urlStr, &title, &visitTime); err != nil {
			continue
		}

		// Convert Timestamp
		ts := webkitEpoch.Add(time.Duration(visitTime) * time.Microsecond)

		callback(model.TimelineEvent{
			EventTime: ts,
			Source:    "Browser",
			Artifact:  browser + " History",
			Action:    "Page Visit",
			Details: map[string]string{
				"URL":   urlStr,
				"Title": title,
			},
			EvidenceRef: model.EvidenceRef{
				SourcePath: path,
			},
		})
	}

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
