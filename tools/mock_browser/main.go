package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

func main() {
	fmt.Println("=== GTrace Browser Mock Generator ===")

	// 模拟 Chrome 路径
	mockPath := filepath.Join(os.TempDir(), "gtrace_mock_history")
	os.Remove(mockPath) // 重新开始

	db, err := sql.Open("sqlite", mockPath)
	if err != nil {
		fmt.Printf("Error creating mock DB: %v\n", err)
		return
	}
	defer db.Close()

	// 1. 创建 Chrome 核心表结构
	_, err = db.Exec(`
		CREATE TABLE urls(
			id INTEGER PRIMARY KEY,
			url TEXT,
			title TEXT,
			visit_count INTEGER,
			last_visit_time INTEGER
		);
		CREATE TABLE visits(
			id INTEGER PRIMARY KEY,
			url INTEGER,
			visit_time INTEGER,
			from_visit INTEGER,
			transition INTEGER
		);
	`)
	if err != nil {
		fmt.Printf("Error creating schema: %v\n", err)
		return
	}

	// 2. 插入模拟的可疑数据 (2026-01-19 左右的时间戳)
	// Chrome 使用的是 WebKit Epoch (1601-01-01 以来的微秒)
	nowWebKit := int64(13412599200000000) // 约 2026 年

	urls := []struct {
		url   string
		title string
	}{
		{"https://evil-phishing.com/login", "Office 365 Login"},
		{"https://github.com/mimikatz/releases", "Mimikatz Download"},
		{"http://192.168.1.50/payload.exe", "Internal Resource"},
	}

	for i, u := range urls {
		_, err = db.Exec("INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
			i+1, u.url, u.title, 1, nowWebKit+(int64(i)*1000000))
	}

	fmt.Printf("[+] Mock History created at: %s\n", mockPath)
	fmt.Println("[!] You can point GTrace to this file in 'Offline Mode' or rename it to 'History' to test.")
}
