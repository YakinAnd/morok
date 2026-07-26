package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Serve loads the report at path and runs an MCP server over stdio,
// exposing shared, blueteam, and redteam tools over its findings. Blocks
// until the transport closes (client disconnects) or ctx is done.
func Serve(ctx context.Context, path string) error {
	snap, err := ParseReport(path)
	if err != nil {
		return fmt.Errorf("loading report: %w", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "morok", Version: "1.2.2"}, nil)

	registerSharedTools(server, snap)

	return server.Run(ctx, &mcp.StdioTransport{})
}
