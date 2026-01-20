package main

import (
	"fmt"
	"gtrace/internal/analysis"
	"gtrace/pkg/model"
	"strings"
)

func main() {
	fmt.Println("=== GTrace Logic Verification Tool (Mock Mode) ===")

	// 1. 初始化最新的 Sigma 引擎
	// 使用 nil FS 因为我们主要测试内建规则和映射逻辑
	engine, err := analysis.NewEngineV2(nil, "")
	if err != nil {
		fmt.Printf("Error initializing engine: %v\n", err)
		return
	}
	fmt.Printf("[+] Sigma Engine initialized with %d rules\n", len(engine.Rules))

	// 2. 验证 Sigma 字段映射与命中
	fmt.Println("\n--- Scenario 1: Sigma Mapping & Detection ---")

	// 模拟一条 4688 事件，但使用非标准的字段名（模拟解析器的各种输出）
	testEvent := model.TimelineEvent{
		Source:   "EventLog",
		Artifact: "Security",
		Details: map[string]string{
			"EventID":        "4688",
			"NewProcessName": `C:\Windows\System32\whoami.exe`, // 映射到 Image
			"_CommandLine":   "whoami /all",                    // 映射到 CommandLine
		},
	}

	if matched := engine.Evaluate(testEvent); matched != nil {
		fmt.Printf("[OK] Detected: %s (Level: %s)\n", matched.Title, matched.Level)
		fmt.Printf("     MITRE: %v\n", strings.Join(matched.Tags, ", "))
	} else {
		fmt.Println("[FAIL] Rule not matched. Mapping might be broken.")
	}

	// 模拟一条 PowerShell 编码攻击
	psEvent := model.TimelineEvent{
		Source: "EventLog",
		Details: map[string]string{
			"EventID":     "4688",
			"ExePath":     `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"CommandLine": "powershell.exe -enc V2hvYW1p", // 验证映射逻辑
		},
	}
	if matched := engine.Evaluate(psEvent); matched != nil {
		fmt.Printf("[OK] Detected: %s (Level: %s)\n", matched.Title, matched.Level)
	}

	// 3. 验证公平性限额逻辑 (Fairness Cap Simulation)
	fmt.Println("\n--- Scenario 2: Fairness Cap Optimization ---")

	writtenCount := 0
	bulkCounts := make(map[string]int)
	bulkLimit := 10 // 模拟很小的限额

	// 模拟流数据
	mockEvents := []string{
		"EventLog", "EventLog", "EventLog", "EventLog", "EventLog", "EventLog", "EventLog", "EventLog",
		"Registry", "Registry", "Registry",
		"Network", "Network",
	}

	fmt.Println("Processing events with 10 event limit and 60% fairness cap:")
	for _, source := range mockEvents {
		cat := "Other"
		if source == "EventLog" {
			cat = "EventLog"
		}
		if source == "Registry" {
			cat = "Registry"
		}

		isBulk := (cat == "EventLog" || cat == "Registry")

		// 模拟 Pipeline 中的逻辑
		if isBulk {
			if writtenCount >= bulkLimit {
				fmt.Printf(" [SKIP] %s - Global Limit reached\n", source)
				continue
			}
			if bulkCounts[cat] >= (bulkLimit * 6 / 10) {
				fmt.Printf(" [SKIP] %s - Fairness Cap (60%%) triggered\n", source)
				continue
			}
		}

		// 写入
		writtenCount++
		if isBulk {
			bulkCounts[cat]++
		}
		fmt.Printf(" [WRITE] %s (Count: %d, CatCount: %d)\n", source, writtenCount, bulkCounts[cat])
	}

	fmt.Println("\n[!] Conclusion: Even with high EventLog volume, Registry and high-value data get through.")
}
