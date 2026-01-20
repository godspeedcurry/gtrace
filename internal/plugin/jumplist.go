package plugin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"

	lnk "github.com/parsiya/golnk"
	"www.velocidex.com/golang/oleparse"
)

type JumplistParser struct{}

func (p *JumplistParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-jumplist-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/octet-stream",
		},
		Output: pluginsdk.IODecl{
			Artifact: "jumplist", // automaticDestinations-ms
		},
	}
}

func (p *JumplistParser) CanParse(path string, header []byte) bool {
	if strings.HasSuffix(strings.ToLower(path), ".automaticdestinations-ms") {
		return true
	}
	return false
}

func (p *JumplistParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	// Read file fully into memory
	content, err := os.ReadFile(in.EvidencePath)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %w", err)
	}

	// Parse OLE
	oleFile, err := oleparse.NewOLEFile(content)
	if err != nil {
		return nil, fmt.Errorf("oleparse failed: %w", err)
	}

	var events []model.TimelineEvent

	// Iterate OLE Directory entries to find Streams
	for _, dir := range oleFile.Directory {
		// Mse type 2 is Stream
		if dir.Header.Mse != 2 {
			continue
		}

		// Some streams are metadata (DestList), skip known non-LNK ones if needed
		// But in AutomaticDestinations-ms, usually streams are hex IDs = LNK.
		// There is often a "DestList" stream which is not an LNK, but a header.
		// golnk.Read will fail on it, effectively skipping it.

		// Open stream data
		payload, err := oleFile.OpenStreamByName(dir.Name)
		if err != nil {
			continue
		}

		// Skip empty or too small
		if len(payload) < 76 { // Min LNK header size
			continue
		}

		// Parse LNK from bytes
		// lnk.Read takes a Reader and max size
		lnkObj, err := lnk.Read(bytes.NewReader(payload), uint64(len(payload)))
		if err != nil {
			continue
		}

		// Extract Data
		// Golnk usually returns utf-8 strings but if the LNK uses local code page (ANSI) AND that page is GBK,
		// golnk might just cast bytes to string or use a default decoder that fails.
		// We try to "repair" the string if it looks damaged, or just treat it as bytes.
		// Since we don't have access to underlying bytes easily without forking golnk,
		// we assume `LocalBasePath` string is `string(original_bytes)`.
		targetPath := BytesToString([]byte(lnkObj.LinkInfo.LocalBasePath))
		if targetPath == "" {
			targetPath = BytesToString([]byte(lnkObj.StringData.RelativePath))
		}

		// Attributes
		args := BytesToString([]byte(lnkObj.StringData.CommandLineArguments))

		// Basic sanity check to remove garbage
		targetPath = CleanString(targetPath)
		args = CleanString(args)

		// Timestamps
		// For Jumplists, the OLE Stream Modification Time is when the entry was updated (User Access)
		// We convert OLE timestamp (Windows FILETIME) to Go Time
		modTime := windowsFiletimeToGo(dir.Header.ModifyTime)

		if !modTime.IsZero() && targetPath != "" {
			events = append(events, model.TimelineEvent{
				ID:        fmt.Sprintf("jump-%s-%d", dir.Name, modTime.UnixNano()),
				EventTime: modTime,
				Source:    "Jumplist",
				Artifact:  "AutomaticDestinations",
				Action:    "Access",
				Subject:   targetPath,
				Details: map[string]string{
					"args":          args,
					"app_id_file":   filepath.Base(in.EvidencePath),
					"stream_name":   dir.Name,
					"target_create": lnkObj.Header.CreationTime.String(),
					"target_mod":    lnkObj.Header.WriteTime.String(),
				},
				EvidenceRef: model.EvidenceRef{
					SourcePath: in.EvidencePath,
				},
			})
		}
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}
