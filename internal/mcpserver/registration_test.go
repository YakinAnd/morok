package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestServerRegistersAllTools builds a server exactly as Serve() does,
// wires it to an in-memory (non-blocking) transport pair, connects a real
// mcp.Client to it, and lists tools — proving all three registerXTools
// calls actually reach a running server and that no two tools collided on
// Name. Uses mcp.NewInMemoryTransports(), not mcp.StdioTransport, so this
// cannot block on stdio like a direct Serve() call would.
func TestServerRegistersAllTools(t *testing.T) {
	snap := testSnapshot()
	server := mcp.NewServer(&mcp.Implementation{Name: "morok", Version: "1.2.2"}, nil)

	registerSharedTools(server, snap)
	registerBlueteamTools(server, snap)
	registerRedteamTools(server, snap)

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	// Servers must be connected before clients (per NewInMemoryTransports doc).
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer clientSession.Close()

	res, err := clientSession.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	want := map[string]bool{
		"get_report_summary":             false,
		"list_categories":                false,
		"list_findings":                  false,
		"get_remediation_checklist":      false,
		"get_vulnerability_summary":      false,
		"list_attack_paths":              false,
		"get_attack_path":                false,
		"list_confirmed_vulnerabilities": false,
	}

	if len(res.Tools) != len(want) {
		names := make([]string, 0, len(res.Tools))
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		t.Fatalf("ListTools returned %d tools %v, want %d: %v", len(res.Tools), names, len(want), want)
	}

	for _, tool := range res.Tools {
		if _, ok := want[tool.Name]; !ok {
			t.Errorf("unexpected tool registered: %q", tool.Name)
			continue
		}
		want[tool.Name] = true
	}

	for name, seen := range want {
		if !seen {
			t.Errorf("expected tool %q was not registered", name)
		}
	}
}
