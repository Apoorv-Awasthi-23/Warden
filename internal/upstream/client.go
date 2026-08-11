package upstream

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/config"
)

func Connect(ctx context.Context, sc config.ServerConfig) (*mcp.ClientSession, error) {
	var transport mcp.Transport

	switch sc.Transport {
	case config.TransportStdio:
		cmd := exec.Command(sc.Command, sc.Args...)
		if len(sc.Env) > 0 {
			cmd.Env = os.Environ()
			for k, v := range sc.Env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
		}
		transport = &mcp.CommandTransport{Command: cmd}
	case config.TransportHTTP:
		transport = &mcp.StreamableClientTransport{
			Endpoint: sc.URL,
		}
	default:
		return nil, fmt.Errorf("server %q: unsupported transport %q", sc.Name, sc.Transport)
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:   "mcp-policy-proxy",
		Version: "0.1.0",
	},nil)
	session, err:= client.Connect(ctx, transport, nil)
	if err!= nil{
		return nil, fmt.Errorf("connecting to server %q: %w", sc.Name, err)
	}
	return session, nil
	}

	func ListTools(ctx context.Context, session *mcp.ClientSession) ([]*mcp.Tool, error) {
		var tools []*mcp.Tool
		for tool, err := range session.Tools(ctx, nil) {
			if err != nil {
				return nil, fmt.Errorf("listing tools: %w", err)
			}
			tools =  append(tools, tool)
		}
		return tools, nil
	}