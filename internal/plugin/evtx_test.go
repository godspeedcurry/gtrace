package plugin

import (
	"context"
	"gtrace/pkg/pluginsdk"
	"path/filepath"
	"testing"
)

func TestEvtxParser_Parse(t *testing.T) {
	// Adjust path to point to your test_demo directory
	cwd, _ := filepath.Abs(".")
	testFile := filepath.Join(cwd, "../../test_demo/Security.evtx")
	// Wait, the test is running inside internal/plugin, so ../../test_demo is correct relative to package root if running locally?
	// Actually absolute path is safer if we know it. But let's try relative first.
	// The user said they put it in `test_demo`.

	p := &EvtxParser{}

	req := pluginsdk.ParseRequest{
		EvidencePath: testFile,
	}

	resp, err := p.Parse(context.Background(), req)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	t.Logf("Parsed %d events", len(resp.Events))
	if len(resp.Events) == 0 {
		t.Error("Expected events, got 0")
	}

	for i, e := range resp.Events {
		if i > 5 {
			break
		}
		t.Logf("Event: %+v", e)
	}
}
