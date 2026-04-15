package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerFetchTools(s *server.MCPServer, client *H1Client) {
	// fetch_reports
	s.AddTool(mcp.NewTool("fetch_reports",
		mcp.WithDescription("Sync ALL your HackerOne reports (any state) into the local database. Incremental — only fetches new reports since last sync. Run once at session start."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return fetchReportsHandler(ctx, client)
	})

	// fetch_programs
	s.AddTool(mcp.NewTool("fetch_programs",
		mcp.WithDescription("Sync all HackerOne programs you have access to into the local database."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return fetchProgramsHandler(ctx, client)
	})

	// fetch_program_scopes
	s.AddTool(mcp.NewTool("fetch_program_scopes",
		mcp.WithDescription("Fetch and store the latest in-scope assets for a specific program."),
		mcp.WithString("handle", mcp.Required(), mcp.Description("Program handle e.g. 'google'")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handle, _ := req.GetArguments()["handle"].(string)
		return fetchScopesHandler(ctx, client, handle)
	})

	// refresh_disclosed_reports
	s.AddTool(mcp.NewTool("refresh_disclosed_reports",
		mcp.WithDescription("Pull recently disclosed HackerOne reports into the local database. Keeps your intelligence current — run periodically."),
		mcp.WithNumber("limit", mcp.Description("Max reports to pull (default 500)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		limit := 500
		if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
			limit = int(v)
		}
		return refreshDisclosedHandler(ctx, client, limit)
	})
}

// --- Handlers ---

func fetchReportsHandler(ctx context.Context, client *H1Client) (*mcp.CallToolResult, error) {
	lastSync := getMeta("reports_last_sync")

	params := url.Values{}
	// Sync ALL report states — not just rewarded
	if lastSync != "" {
		params.Set("filter[created_at][gt]", lastSync)
	}

	raw, err := client.fetchAllPages(ctx, "/hackers/me/reports", params)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	inserted, updated := 0, 0
	for _, r := range raw {
		a := attrs(r)
		if a == nil {
			continue
		}

		// Extract nested fields
		weakData := relData(r, "weakness")
		weakAttrs := attrs(weakData)
		sevData := relData(r, "severity")
		sevAttrs := attrs(sevData)
		progData := relData(r, "program")
		progAttrs := attrs(progData)
		scopeData := relData(r, "structured_scope")
		scopeAttrs := attrs(scopeData)

		// Extract bounty from relationships
		bountyAmount := 0.0
		bountyCurrency := "USD"
		for _, b := range relDataList(r, "bounties") {
			if bm, ok := b.(map[string]any); ok {
				ba := attrs(bm)
				bountyAmount += flt(ba, "awarded_amount")
				if c := str(ba, "awarded_currency"); c != "" {
					bountyCurrency = c
				}
			}
		}

		id := str(r, "id")
		res, err := personalDB.Exec(
			`INSERT INTO reports
				(id, title, state, created_at, bounty_awarded_at, closed_at, disclosed_at,
				 program_handle, weakness_name, weakness_cwe, severity_rating, severity_score,
				 bounty_amount, bounty_currency, vuln_info, asset_identifier, asset_type)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET
				state=excluded.state,
				bounty_awarded_at=excluded.bounty_awarded_at,
				closed_at=excluded.closed_at,
				disclosed_at=excluded.disclosed_at,
				bounty_amount=excluded.bounty_amount,
				bounty_currency=excluded.bounty_currency,
				severity_rating=excluded.severity_rating,
				severity_score=excluded.severity_score,
				vuln_info=excluded.vuln_info`,
			id,
			str(a, "title"),
			str(a, "state"),
			str(a, "created_at"),
			str(a, "bounty_awarded_at"),
			str(a, "closed_at"),
			str(a, "disclosed_at"),
			str(progAttrs, "handle"),
			str(weakAttrs, "name"),
			str(weakAttrs, "external_id"),
			str(sevAttrs, "rating"),
			flt(sevAttrs, "score"),
			bountyAmount,
			bountyCurrency,
			str(a, "vulnerability_information"),
			str(scopeAttrs, "asset_identifier"),
			str(scopeAttrs, "asset_type"),
		)
		if err == nil {
			rows, _ := res.RowsAffected()
			if rows > 0 {
				inserted++
			} else {
				updated++
			}
		}
	}

	setMeta("reports_last_sync", time.Now().UTC().Format(time.RFC3339))

	// Summary by state
	type statRow struct {
		state string
		count int
	}
	rows, _ := personalDB.Query("SELECT state, COUNT(*) FROM reports GROUP BY state ORDER BY COUNT(*) DESC")
	defer rows.Close()
	var statLines []string
	for rows.Next() {
		var s string
		var c int
		rows.Scan(&s, &c)
		statLines = append(statLines, fmt.Sprintf("  %s: %d", s, c))
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"Synced %d reports (%d new/updated).\n\nBreakdown by state:\n%s\n\nLast sync: %s",
		len(raw), inserted+updated,
		strings.Join(statLines, "\n"),
		time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	)), nil
}

func fetchProgramsHandler(ctx context.Context, client *H1Client) (*mcp.CallToolResult, error) {
	raw, err := client.fetchAllPages(ctx, "/hackers/programs", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	for _, p := range raw {
		a := attrs(p)
		if a == nil {
			continue
		}
		personalDB.Exec(
			`INSERT INTO programs (id, handle, name, submission_state, offers_bounties, currency)
			 VALUES (?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET
				handle=excluded.handle, name=excluded.name,
				submission_state=excluded.submission_state,
				offers_bounties=excluded.offers_bounties`,
			str(p, "id"),
			str(a, "handle"),
			str(a, "name"),
			str(a, "submission_state"),
			boolVal(a, "offers_bounties"),
			str(a, "currency"),
		)
	}

	return mcp.NewToolResultText(fmt.Sprintf("Synced %d programs.", len(raw))), nil
}

func fetchScopesHandler(ctx context.Context, client *H1Client, handle string) (*mcp.CallToolResult, error) {
	if handle == "" {
		return mcp.NewToolResultText("handle is required"), nil
	}

	raw, err := client.fetchAllPages(ctx, "/hackers/programs/"+handle+"/structured_scopes", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	personalDB.Exec("DELETE FROM scopes WHERE program_handle = ?", handle)
	for _, s := range raw {
		a := attrs(s)
		if a == nil {
			continue
		}
		personalDB.Exec(
			`INSERT OR REPLACE INTO scopes
				(id, program_handle, asset_identifier, asset_type,
				 eligible_for_bounty, eligible_for_submission, max_severity, instruction)
			 VALUES (?,?,?,?,?,?,?,?)`,
			str(s, "id"), handle,
			str(a, "asset_identifier"), str(a, "asset_type"),
			boolVal(a, "eligible_for_bounty"),
			boolVal(a, "eligible_for_submission"),
			str(a, "max_severity"),
			str(a, "instruction"),
		)
	}

	return mcp.NewToolResultText(fmt.Sprintf("Fetched %d scope assets for '%s'.", len(raw), handle)), nil
}

func refreshDisclosedHandler(ctx context.Context, client *H1Client, limit int) (*mcp.CallToolResult, error) {
	// Pull recently disclosed reports via the H1 API
	params := url.Values{}
	params.Set("filter[state][]", "disclosed")
	params.Set("page[size]", "100")

	raw, err := client.fetchAllPages(ctx, "/hackers/me/reports", params)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	added := 0
	for i, r := range raw {
		if i >= limit {
			break
		}
		a := attrs(r)
		if a == nil {
			continue
		}
		weakData := relData(r, "weakness")
		weakAttrs := attrs(weakData)
		progData := relData(r, "program")
		progAttrs := attrs(progData)
		scopeData := relData(r, "structured_scope")
		scopeAttrs := attrs(scopeData)

		bountyAmount := 0.0
		for _, b := range relDataList(r, "bounties") {
			if bm, ok := b.(map[string]any); ok {
				ba := attrs(bm)
				bountyAmount += flt(ba, "awarded_amount")
			}
		}

		id := str(r, "id")
		var existingID string
		disclosedDB.QueryRow("SELECT id FROM disclosed_reports WHERE id = ?", id).Scan(&existingID)
		if existingID != "" {
			continue // already have it
		}

		_, err := disclosedDB.Exec(
			`INSERT INTO disclosed_reports
				(id, title, vuln_info, weakness_name, program_handle,
				 asset_identifier, asset_type, bounty_amount, disclosed_at)
			 VALUES (?,?,?,?,?,?,?,?,?)`,
			id,
			str(a, "title"),
			str(a, "vulnerability_information"),
			str(weakAttrs, "name"),
			str(progAttrs, "handle"),
			str(scopeAttrs, "asset_identifier"),
			str(scopeAttrs, "asset_type"),
			bountyAmount,
			str(a, "disclosed_at"),
		)
		if err == nil {
			// Keep FTS index in sync
			disclosedDB.Exec(
				"INSERT INTO disclosed_fts(rowid, title, vuln_info) VALUES (?,?,?)",
				id, str(a, "title"), str(a, "vulnerability_information"),
			)
			added++
		}
	}

	var total int
	disclosedDB.QueryRow("SELECT COUNT(*) FROM disclosed_reports").Scan(&total)
	return mcp.NewToolResultText(fmt.Sprintf(
		"Added %d new disclosed reports. Total in database: %d.", added, total,
	)), nil
}
