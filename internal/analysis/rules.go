package analysis

import (
	"fmt"
	"gtrace/pkg/model"
	"strings"
)

// Rule represents a simplified Sigma-like detection rule
type Rule struct {
	ID          string
	Title       string
	Level       string // critical, high, medium, low
	Description string
	Mitre       []string
	Check       func(ev model.TimelineEvent) bool
}

// SigmaEngine holds the rules
type SigmaEngine struct {
	Rules []Rule
}

// NewSigmaEngine initializes the engine with built-in rules
func NewSigmaEngine() *SigmaEngine {
	return &SigmaEngine{
		Rules: GetBuiltinRules(),
	}
}

// GetBuiltinRules returns a hardcoded list of high-value detection rules
func GetBuiltinRules() []Rule {
	return []Rule{
		{
			ID:          "proc_recon_whoami",
			Title:       "Whoami Execution",
			Level:       "medium",
			Description: "Feature: System Owner/User Discovery. Identify usage of whoami.exe.",
			Mitre:       []string{"T1033"},
			Check: func(ev model.TimelineEvent) bool {
				// EventID 4688: Process Creation
				if getDetail(ev, "EventID") != "4688" {
					return false
				}
				process := strings.ToLower(getDetail(ev, "NewProcessName"))
				cmd := strings.ToLower(getDetail(ev, "CommandLine"))

				return strings.Contains(process, "whoami.exe") || strings.Contains(cmd, "whoami")
			},
		},
		{
			ID:          "proc_susp_powershell_enc",
			Title:       "Suspicious Encoded PowerShell",
			Level:       "high",
			Description: "Detects usage of -enc/-encodedcommand in PowerShell",
			Mitre:       []string{"T1059.001"},
			Check: func(ev model.TimelineEvent) bool {
				if getDetail(ev, "EventID") != "4688" {
					return false
				}
				process := strings.ToLower(getDetail(ev, "NewProcessName"))
				cmd := strings.ToLower(getDetail(ev, "CommandLine"))

				if strings.Contains(process, "powershell") || strings.Contains(process, "pwsh") {
					if strings.Contains(cmd, " -enc") || strings.Contains(cmd, " -e ") {
						return true
					}
				}
				return false
			},
		},
		{
			ID:          "proc_cred_dump_lsass",
			Title:       "Potential LSASS Dumping",
			Level:       "critical",
			Description: "Detects patterns associated with LSASS credential dumping (e.g. procdump, comsvcs)",
			Mitre:       []string{"T1003.001"},
			Check: func(ev model.TimelineEvent) bool {
				if getDetail(ev, "EventID") != "4688" {
					return false
				}
				cmd := strings.ToLower(getDetail(ev, "CommandLine"))

				// comsvcs.dll dumping
				if strings.Contains(cmd, "comsvcs.dll") && strings.Contains(cmd, "minidump") {
					return true
				}
				// procdump
				if strings.Contains(cmd, "procdump") && strings.Contains(cmd, "lsass") {
					return true
				}
				return false
			},
		},
		{
			ID:          "proc_recon_net",
			Title:       "Network/User Reconnaissance",
			Level:       "low",
			Description: "Usage of net.exe for reconnaissance",
			Mitre:       []string{"T1087", "T1069"},
			Check: func(ev model.TimelineEvent) bool {
				if getDetail(ev, "EventID") != "4688" {
					return false
				}
				process := strings.ToLower(getDetail(ev, "NewProcessName"))
				if strings.Contains(process, "net.exe") || strings.Contains(process, "net1.exe") {
					cmd := strings.ToLower(getDetail(ev, "CommandLine"))
					if strings.Contains(cmd, " group") || strings.Contains(cmd, " user") || strings.Contains(cmd, " localgroup") {
						return true
					}
				}
				return false
			},
		},
		// Generic Critical Process Access (simplified)
		{
			ID:          "sys_critical_process_access",
			Title:       "Critical Process Access",
			Level:       "high",
			Description: "Access to critical processes like LSASS",
			Mitre:       []string{"T1003"},
			Check: func(ev model.TimelineEvent) bool {
				if getDetail(ev, "EventID") == "4663" || getDetail(ev, "EventID") == "4656" {
					obj := strings.ToLower(getDetail(ev, "ObjectName"))
					if strings.Contains(obj, "lsass.exe") {
						return true
					}
				}
				return false
			},
		},
		{
			ID:          "proc_persist_schtasks",
			Title:       "Scheduled Task Creation",
			Level:       "high",
			Description: "Detects creation of scheduled tasks via command line",
			Mitre:       []string{"T1053.005"},
			Check: func(ev model.TimelineEvent) bool {
				if getDetail(ev, "EventID") != "4688" {
					return false
				}
				process := strings.ToLower(getDetail(ev, "NewProcessName"))
				cmd := strings.ToLower(getDetail(ev, "CommandLine"))

				if strings.Contains(process, "schtasks") && strings.Contains(cmd, "/create") {
					return true
				}
				return false
			},
		},
		{
			ID:          "proc_mod_reg",
			Title:       "Suspicious Registry Modification",
			Level:       "medium",
			Description: "Detects usage of reg.exe to add keys",
			Mitre:       []string{"T1112"},
			Check: func(ev model.TimelineEvent) bool {
				if getDetail(ev, "EventID") != "4688" {
					return false
				}
				process := strings.ToLower(getDetail(ev, "NewProcessName"))
				if strings.Contains(process, "reg.exe") {
					cmd := strings.ToLower(getDetail(ev, "CommandLine"))
					if strings.Contains(cmd, " add ") || strings.Contains(cmd, " import ") {
						return true
					}
				}
				return false
			},
		},
		{
			ID:          "proc_tool_bitsadmin",
			Title:       "Bitsadmin Download",
			Level:       "high",
			Description: "Detects usage of bitsadmin to download files",
			Mitre:       []string{"T1197"},
			Check: func(ev model.TimelineEvent) bool {
				if getDetail(ev, "EventID") != "4688" {
					return false
				}
				cmd := strings.ToLower(getDetail(ev, "CommandLine"))
				if strings.Contains(cmd, "bitsadmin") && strings.Contains(cmd, "/transfer") {
					return true
				}
				return false
			},
		},
	}
}

// Helper to get detail safely
func getDetail(ev model.TimelineEvent, key string) string {
	if val, ok := ev.Details[key]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", val))
	}
	return ""
}
