package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	// Load .env if present (falls back to real env vars if not)
	_ = godotenv.Load()

	username := os.Getenv("H1_USERNAME")
	token := os.Getenv("H1_API_TOKEN")
	if username == "" || token == "" {
		log.Fatal("[hack-with-MCP] H1_USERNAME and H1_API_TOKEN must be set")
	}

	// Init databases
	if err := initPersonalDB(); err != nil {
		log.Fatalf("[hack-with-MCP] personal DB init failed: %v", err)
	}
	if err := initDisclosedDB(); err != nil {
		log.Fatalf("[hack-with-MCP] disclosed DB init failed: %v", err)
	}

	// Build H1 API client
	client := newH1Client(username, token)

	// Create MCP server
	s := server.NewMCPServer(
		"hack-with-MCP",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// --- Register all tools ---
	registerFetchTools(s, client)
	registerSearchTools(s)
	registerHackTools(s, client)
	registerReportTools(s, client)
	registerProgramTools(s, client)
	registerWriteTools(s, client)

	log.Println("[hack-with-MCP] server started")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("[hack-with-MCP] server error: %v", err)
	}
}
