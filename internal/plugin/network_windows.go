//go:build windows

package plugin

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"gtrace/pkg/model"
)

// CollectNetwork gathers volatile network information from the live system.
// It executes system commands (netstat, ipconfig, arp) and emits events via the callback.
func CollectNetwork(ctx context.Context, callback func(model.TimelineEvent)) error {
	// 1. Netstat (Active Connections)
	if err := collectNetstat(ctx, callback); err != nil {
		fmt.Printf("Error collecting netstat: %v\n", err)
	}

	// 2. ARP Table
	if err := collectARP(ctx, callback); err != nil {
		fmt.Printf("Error collecting ARP: %v\n", err)
	}

	// 3. IP Configuration
	if err := collectIPConfig(ctx, callback); err != nil {
		fmt.Printf("Error collecting IPConfig: %v\n", err)
	}

	return nil
}

// collectNetstat runs 'netstat -ano' and parses the output.
func collectNetstat(ctx context.Context, callback func(model.TimelineEvent)) error {
	cmd := exec.CommandContext(ctx, "netstat", "-ano")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Fix Encoding (GBK -> UTF8)
	decoded := BytesToString(output)
	scanner := bufio.NewScanner(strings.NewReader(decoded))

	now := time.Now()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip headers (English or Chinese or Empty)
		// English: "Proto", "Active Connections"
		// Chinese: "协议", "活动连接"
		if line == "" || strings.HasPrefix(line, "Proto") || strings.HasPrefix(line, "Active") ||
			strings.HasPrefix(line, "协议") || strings.HasPrefix(line, "活动") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		var proto, local, foreign, state, pid string

		proto = fields[0]
		local = fields[1]
		foreign = fields[2]

		// UDP doesn't always have state
		if strings.EqualFold(proto, "UDP") {
			// UDP 0.0.0.0:123 *:* 1234
			if len(fields) == 4 {
				pid = fields[3]
				state = "N/A"
			} else if len(fields) >= 5 {
				state = fields[3]
				pid = fields[4]
			}
		} else {
			// TCP
			if len(fields) >= 5 {
				state = fields[3]
				pid = fields[4]
			} else {
				// Sometimes state is missing or fields are merged? Unlikely for TCP output structure.
				// But handle bounds just in case.
				state = "UNKNOWN"
				if len(fields) > 3 {
					pid = fields[3] // Fallback
				}
			}
		}

		callback(model.TimelineEvent{
			EventTime: now,
			Source:    "Network",
			Artifact:  "Network Connection",
			Action:    "Connect",
			Subject:   foreign,
			Details: map[string]string{
				"Protocol": proto,
				"LocalIP":  local,
				"RemoteIP": foreign,
				"State":    state,
				"PID":      pid,
				"Command":  "netstat -ano",
				"EventID":  "CONN",
			},
			EvidenceRef: model.EvidenceRef{
				SourcePath: "Live Command: netstat",
			},
		})
	}

	return nil
}

// collectARP runs 'arp -a'
func collectARP(ctx context.Context, callback func(model.TimelineEvent)) error {
	cmd := exec.CommandContext(ctx, "arp", "-a")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	decoded := BytesToString(output)
	scanner := bufio.NewScanner(strings.NewReader(decoded))
	now := time.Now()
	var currentInterface string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// English: "Interface:", "Internet Address"
		// Chinese: "接口:", "Internet 地址"
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Interface:") || strings.HasPrefix(line, "接口:") {
			currentInterface = line
			continue
		}
		if strings.HasPrefix(line, "Internet") { // Works for both English and Chinese ("Internet 地址")
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// IP, MAC, Type
		callback(model.TimelineEvent{
			EventTime: now,
			Source:    "Network",
			Artifact:  "ARP Entry",
			Action:    "Resolve",
			Subject:   fields[0], // The IP
			Details: map[string]string{
				"Interface": currentInterface,
				"IP":        fields[0],
				"MAC":       fields[1],
				"Type":      fields[2],
				"EventID":   "ARP",
			},
			EvidenceRef: model.EvidenceRef{
				SourcePath: "Live Command: arp -a",
			},
		})
	}
	return nil
}

// collectIPConfig runs 'ipconfig /all'
func collectIPConfig(ctx context.Context, callback func(model.TimelineEvent)) error {
	cmd := exec.CommandContext(ctx, "ipconfig", "/all")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	decoded := BytesToString(output)
	scanner := bufio.NewScanner(strings.NewReader(decoded))
	var currentAdapter string

	now := time.Now()

	for scanner.Scan() {
		line := scanner.Text() // Keep indentation
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		// Adapter line usually starts at col 0 and ends with ":"
		// Multi-lingual safe assumption: line has no leading space, contains "adapter" (English) or "适配器" (Chinese)?
		// Actually "Ethernet adapter Ethernet:" -> "以太网适配器 以太网:"
		if !strings.HasPrefix(line, "   ") && strings.HasSuffix(trimmed, ":") {
			currentAdapter = strings.TrimSuffix(trimmed, ":")
			continue
		}

		if currentAdapter != "" {
			// We are inside an adapter block
			// Check for Physical Address (物理地址) and IPv4 Address (IPv4 地址)
			if strings.Contains(trimmed, "Physical Address") || strings.Contains(trimmed, "物理地址") ||
				strings.Contains(trimmed, "IPv4") {

				// Key. . . . . : Value
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(strings.ReplaceAll(parts[0], ".", ""))
					val := strings.TrimSpace(parts[1])
					// Remove "(Preferred)" / "(首选)" etc from IP
					if idx := strings.Index(val, "("); idx > 0 {
						val = strings.TrimSpace(val[:idx])
					}

					callback(model.TimelineEvent{
						EventTime: now,
						Source:    "Network",
						Artifact:  "Interface Config",
						Action:    "Configure",
						Subject:   currentAdapter,
						Details: map[string]string{
							"Adapter": currentAdapter,
							"Key":     key,
							"Value":   val,
							"EventID": "IPCFG",
						},
						EvidenceRef: model.EvidenceRef{
							SourcePath: "Live Command: ipconfig /all",
						},
					})
				}
			}
		}
	}

	return nil
}
