package plugin

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"

	"www.velocidex.com/golang/regparser"
)

type SAMParser struct{}

func (p *SAMParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-sam-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/octet-stream",
		},
		Output: pluginsdk.IODecl{
			Artifact: "user_account",
		},
	}
}

func (p *SAMParser) CanParse(path string, header []byte) bool {
	// Robust checks for SAM hive
	base := strings.ToUpper(filepath.Base(path))
	// Check filename or header magic
	if strings.Contains(base, "SAM") || base == "SAM" {
		if len(header) >= 4 && string(header[:4]) == "regf" {
			return true
		}
	}
	// Fallback for generic dump names containing SAM
	if strings.Contains(strings.ToUpper(path), "SAM") && len(header) >= 4 && string(header[:4]) == "regf" {
		return true
	}
	return false
}

func (p *SAMParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	f, err := os.Open(in.EvidencePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("open registry: %w", err)
	}

	// Dynamic Search for "Users" key to handle different mounting points (ROOT/SAM/...)
	var accountKey *regparser.CM_KEY_NODE
	found := false

	var finder func(k *regparser.CM_KEY_NODE)
	finder = func(k *regparser.CM_KEY_NODE) {
		if found || k == nil {
			return
		}

		// Heuristic: Key named "Users" containing "000001F4" (Admin RID) or "Names"
		if strings.EqualFold(k.Name(), "Users") {
			// Validate structure by looking for "Names" subkey
			for _, sub := range k.Subkeys() {
				if strings.EqualFold(sub.Name(), "Names") {
					accountKey = k
					found = true
					return
				}
			}
		}

		// Breadth check first? No, depth is fine, SAM structure is shallow.
		for _, sub := range k.Subkeys() {
			finder(sub)
			if found {
				return
			}
		}
	}

	finder(reg.OpenKey("."))

	if accountKey == nil {
		return nil, fmt.Errorf("SAM Users key not found")
	}

	var events []model.TimelineEvent

	// Iterate Users by RID (Hex keys)
	for _, userKey := range accountKey.Subkeys() {
		ridName := userKey.Name()
		if strings.EqualFold(ridName, "Names") {
			continue
		}

		// Parse F and V values
		var fVal, vVal *regparser.CM_KEY_VALUE
		for _, v := range userKey.Values() {
			if strings.EqualFold(v.Name(), "F") {
				fVal = v
			}
			if strings.EqualFold(v.Name(), "V") {
				vVal = v
			}
		}

		if fVal == nil || vVal == nil {
			continue
		}

		// Retrieve Data
		// Need robust ValueData handling
		fDataFunc := fVal.ValueData()
		vDataFunc := vVal.ValueData()
		if fDataFunc == nil || vDataFunc == nil {
			continue
		}

		fData := fDataFunc.Data
		vData := vDataFunc.Data

		if len(fData) < 48 {
			continue
		}

		// --- Parse F (Fixed Data) ---
		// Offset 8: Last Logon (FILETIME)
		// Offset 24: Password Last Set (FILETIME)

		lastLogon := windowsFiletimeToGo(uint64(binary.LittleEndian.Uint64(fData[8:16])))
		pwdLastSet := windowsFiletimeToGo(uint64(binary.LittleEndian.Uint64(fData[24:32])))

		// ACB Bits (Action Control Bits) at 0x38 (56 dec)
		acb := uint16(0)
		if len(fData) >= 58 {
			acb = binary.LittleEndian.Uint16(fData[56:58])
		}

		// Bit 0 (0x01) usually means Disabled
		isDisabled := (acb & 0x01) != 0

		// --- Parse V (Variable Data) ---
		// Username is usually first item.
		// Standard Offset bias is 0xCC (204).
		// Name Offset at 0x0C, Length at 0x10.

		if len(vData) < 0x20 {
			continue
		}

		nameOffset := binary.LittleEndian.Uint32(vData[0x0C:0x10]) + 0xCC
		nameLen := binary.LittleEndian.Uint32(vData[0x10:0x14])

		username := "Unknown"
		if uint32(len(vData)) >= nameOffset+nameLen {
			username = cleanupUTF16(vData[nameOffset : nameOffset+nameLen])
		}

		// Full Name
		// Offset 0x18, Len 0x1C
		fullOffset := binary.LittleEndian.Uint32(vData[0x18:0x1C]) + 0xCC
		fullLen := binary.LittleEndian.Uint32(vData[0x1C:0x20])
		fullname := ""
		if uint32(len(vData)) >= fullOffset+fullLen {
			fullname = cleanupUTF16(vData[fullOffset : fullOffset+fullLen])
		}

		// --- Shadow / Backdoor Checks ---
		props := map[string]string{
			"Username":   username,
			"RID":        ridName,
			"Fullname":   fullname,
			"Disabled":   fmt.Sprintf("%v", isDisabled),
			"LastLogon":  lastLogon.String(),
			"PwdLastSet": pwdLastSet.String(),
		}

		ridVal, _ := strconv.ParseUint(ridName, 16, 64)

		// 1. Guest Account Active? (RID 501)
		if ridVal == 501 && !isDisabled {
			props["_Alert"] = "Guest Account is ACTIVE (Potential Backdoor)"
		}

		// 2. Hidden Admin? (RID 500 but renamed?)
		if ridVal == 500 && strings.ToLower(username) != "administrator" {
			props["_Info"] = fmt.Sprintf("Renamed Administrator Account: %s", username)
		}

		// Event Time Strategy:
		// Identify "Active" users via LastLogon.
		// If LastLogon is zero (never), use PwdLastSet.
		// If both zero, use Now() but mark as "Never Logged In".

		evtTime := lastLogon
		action := "User Last Logon"
		if evtTime.IsZero() || evtTime.Year() < 1970 {
			evtTime = pwdLastSet
			action = "User Password Set"
		}

		// Ensure non-zero time for timeline visibility
		// If still zero, we might skip or use "found time"
		if evtTime.IsZero() || evtTime.Year() < 1970 {
			// Skipping timeline event for inactive default accounts?
			// Or show them?
			// Let's show them for inventory.
			// Currently Timeline needs valid time?
			// Actually let's include them.
		}

		events = append(events, model.TimelineEvent{
			ID:        fmt.Sprintf("user-%s-%d", ridName, evtTime.UnixNano()),
			EventTime: evtTime,
			Source:    "SAM",
			Artifact:  "UserAccount",
			Action:    action,
			Subject:   username,
			Details:   props,
			EvidenceRef: model.EvidenceRef{
				SourcePath: in.EvidencePath,
			},
		})
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}
