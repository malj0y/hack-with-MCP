package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerIntigritiTools(s *server.MCPServer, client *IntigritiClient) {
	s.AddTool(mcp.NewTool("intigriti_fetch_programs",
		mcp.WithDescription("Sync all Intigriti programs you have access to into the local database."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return intigrititFetchProgramsHandler(ctx, client)
	})

	s.AddTool(mcp.NewTool("intigriti_fetch_submissions",
		mcp.WithDescription("Sync all your Intigriti submissions into the local database. Run once at session start."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return intigritieFetchSubmissionsHandler(ctx, client)
	})

	s.AddTool(mcp.NewTool("intigriti_get_program",
		mcp.WithDescription("Get detailed info and full scope (in-scope and out-of-scope targets) for an Intigriti program."),
		mcp.WithString("program_id", mcp.Required(), mcp.Description("Program ID or handle")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["program_id"].(string)
		return intigritiGetProgramHandler(ctx, client, id)
	})

	s.AddTool(mcp.NewTool("intigriti_search_programs",
		mcp.WithDescription("Search your synced Intigriti programs."),
		mcp.WithString("query", mcp.Description("Handle or name search")),
		mcp.WithString("bounty_only", mcp.Description("'true' to filter bounty programs only")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return intigritiSearchProgramsHandler(req)
	})

	s.AddTool(mcp.NewTool("intigriti_search_submissions",
		mcp.WithDescription("Search your Intigriti submissions stored locally."),
		mcp.WithString("query", mcp.Description("Title keyword")),
		mcp.WithString("program", mcp.Description("Program name or ID filter")),
		mcp.WithString("severity", mcp.Description("low | medium | high | critical")),
		mcp.WithString("status", mcp.Description("Triage | Accepted | Closed | Resolved | Duplicate")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return intigritiSearchSubmissionsHandler(req)
	})
}

// --- Handlers ---

func intigrititFetchProgramsHandler(ctx context.Context, client *IntigritiClient) (*mcp.CallToolResult, error) {
	programs, err := client.getList(ctx, "/programs", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	upserted := 0
	for _, p := range programs {
		id := istr(p, "id")
		handle := istr(p, "handle")
		name := istr(p, "name")
		status := ival(p, "status")
		rewardType := ival(p, "rewardType")
		minVal, currency := ibounty(p, "minBounty")
		maxVal, _ := ibounty(p, "maxBounty")

		_, err := personalDB.Exec(
			`INSERT INTO intigriti_programs (id, handle, name, status, reward_type, min_bounty, max_bounty, currency)
			 VALUES (?,?,?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET
				handle=excluded.handle, name=excluded.name, status=excluded.status,
				reward_type=excluded.reward_type, min_bounty=excluded.min_bounty,
				max_bounty=excluded.max_bounty, currency=excluded.currency`,
			id, handle, name, status, rewardType, minVal, maxVal, currency,
		)
		if err == nil {
			upserted++
		}

		// Sync scope targets
		targets, _ := p["targets"].(map[string]any)
		if targets != nil {
			personalDB.Exec("DELETE FROM intigriti_scopes WHERE program_id = ?", id)
			syncIntigritiTargets(id, targets["inScope"], true)
			syncIntigritiTargets(id, targets["outOfScope"], false)
		}
	}

	setMeta("intigriti_programs_last_sync", time.Now().UTC().Format(time.RFC3339))
	return mcp.NewToolResultText(fmt.Sprintf("Synced %d Intigriti programs.", upserted)), nil
}

func syncIntigritiTargets(programID string, raw any, inScope bool) {
	items, _ := raw.([]any)
	inScopeInt := 0
	if inScope {
		inScopeInt = 1
	}
	for _, item := range items {
		t, ok := item.(map[string]any)
		if !ok {
			continue
		}
		endpoint := istr(t, "endpoint")
		targetType := ival(t, "type")
		tier := ival(t, "tier")
		desc := istr(t, "description")
		id := fmt.Sprintf("%s::%s::%d", programID, endpoint, inScopeInt)

		personalDB.Exec(
			`INSERT OR REPLACE INTO intigriti_scopes (id, program_id, endpoint, type, tier, description, in_scope)
			 VALUES (?,?,?,?,?,?,?)`,
			id, programID, endpoint, targetType, tier, desc, inScopeInt,
		)
	}
}

func intigritieFetchSubmissionsHandler(ctx context.Context, client *IntigritiClient) (*mcp.CallToolResult, error) {
	submissions, err := client.getList(ctx, "/submissions", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	inserted, updated := 0, 0
	for _, s := range submissions {
		id := istr(s, "id")
		title := istr(s, "title")
		status := ival(s, "status")
		severity := ival(s, "severity")
		vulnType := ival(s, "type")
		createdAt := istr(s, "createdAt")
		closedAt := istr(s, "closedAt")

		prog, _ := s["program"].(map[string]any)
		programID := istr(prog, "id")
		programName := istr(prog, "name")

		asset, _ := s["asset"].(map[string]any)
		assetVal := istr(asset, "value")
		assetType := ival(asset, "type")

		bountyVal, currency := ibounty(s, "bounty")

		res, err := personalDB.Exec(
			`INSERT INTO intigriti_submissions
				(id, title, status, severity, vuln_type, program_id, program_name,
				 asset, asset_type, bounty, currency, created_at, closed_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET
				status=excluded.status, severity=excluded.severity,
				bounty=excluded.bounty, currency=excluded.currency, closed_at=excluded.closed_at`,
			id, title, status, severity, vulnType, programID, programName,
			assetVal, assetType, bountyVal, currency, createdAt, closedAt,
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

	setMeta("intigriti_submissions_last_sync", time.Now().UTC().Format(time.RFC3339))
	return mcp.NewToolResultText(fmt.Sprintf(
		"Synced %d Intigriti submissions (%d new, %d updated).",
		len(submissions), inserted, updated,
	)), nil
}

func intigritiGetProgramHandler(ctx context.Context, client *IntigritiClient, programID string) (*mcp.CallToolResult, error) {
	if programID == "" {
		return mcp.NewToolResultText("program_id is required"), nil
	}

	p, err := client.get(ctx, "/programs/"+programID, nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	var sb strings.Builder
	name := istr(p, "name")
	handle := istr(p, "handle")
	status := ival(p, "status")
	rewardType := ival(p, "rewardType")
	minVal, currency := ibounty(p, "minBounty")
	maxVal, _ := ibounty(p, "maxBounty")

	sb.WriteString(fmt.Sprintf("# %s (%s)\n\n", name, handle))
	sb.WriteString(fmt.Sprintf("**Status:** %s\n", status))
	sb.WriteString(fmt.Sprintf("**Reward Type:** %s\n", rewardType))
	if minVal > 0 || maxVal > 0 {
		sb.WriteString(fmt.Sprintf("**Bounty Range:** %.0f – %.0f %s\n", minVal, maxVal, currency))
	}

	targets, _ := p["targets"].(map[string]any)
	if targets != nil {
		inScope, _ := targets["inScope"].([]any)
		outScope, _ := targets["outOfScope"].([]any)

		if len(inScope) > 0 {
			sb.WriteString(fmt.Sprintf("\n## In-Scope Targets (%d)\n\n", len(inScope)))
			for _, item := range inScope {
				t, ok := item.(map[string]any)
				if !ok {
					continue
				}
				tier := ival(t, "tier")
				tierStr := ""
				if tier != "" {
					tierStr = fmt.Sprintf(" [%s]", tier)
				}
				sb.WriteString(fmt.Sprintf("- `%s` (%s)%s\n", istr(t, "endpoint"), ival(t, "type"), tierStr))
				if desc := istr(t, "description"); desc != "" {
					sb.WriteString("  > " + desc + "\n")
				}
			}
		}

		if len(outScope) > 0 {
			sb.WriteString(fmt.Sprintf("\n## Out-of-Scope Targets (%d)\n\n", len(outScope)))
			for _, item := range outScope {
				t, ok := item.(map[string]any)
				if !ok {
					continue
				}
				sb.WriteString(fmt.Sprintf("- `%s` (%s)\n", istr(t, "endpoint"), ival(t, "type")))
			}
		}
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func intigritiSearchProgramsHandler(req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, _ := req.GetArguments()["query"].(string)
	bountyOnly, _ := req.GetArguments()["bounty_only"].(string)
	limit := 20
	if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}

	var conds []string
	var args []any
	if query != "" {
		conds = append(conds, "(handle LIKE ? OR name LIKE ?)")
		args = append(args, "%"+query+"%", "%"+query+"%")
	}
	if bountyOnly == "true" {
		conds = append(conds, "reward_type = 'Bounty'")
	}
	where := "1=1"
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}
	args = append(args, limit)

	rows, err := personalDB.Query(
		fmt.Sprintf(`SELECT id, handle, name, status, reward_type, min_bounty, max_bounty, currency
		 FROM intigriti_programs WHERE %s ORDER BY name LIMIT ?`, where),
		args...,
	)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	for rows.Next() {
		var id, handle, name, status, rewardType, currency string
		var minB, maxB float64
		rows.Scan(&id, &handle, &name, &status, &rewardType, &minB, &maxB, &currency)
		bountyStr := ""
		if minB > 0 || maxB > 0 {
			bountyStr = fmt.Sprintf(" [%.0f–%.0f %s]", minB, maxB, currency)
		}
		lines = append(lines, fmt.Sprintf("- **%s** (%s) — %s — %s%s", name, handle, status, rewardType, bountyStr))
	}

	if len(lines) == 0 {
		return mcp.NewToolResultText("No Intigriti programs found. Run intigriti_fetch_programs first."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d Intigriti programs:\n\n%s", len(lines), strings.Join(lines, "\n"))), nil
}

func intigritiSearchSubmissionsHandler(req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, _ := req.GetArguments()["query"].(string)
	program, _ := req.GetArguments()["program"].(string)
	severity, _ := req.GetArguments()["severity"].(string)
	status, _ := req.GetArguments()["status"].(string)
	limit := 20
	if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}

	var conds []string
	var args []any
	if query != "" {
		conds = append(conds, "title LIKE ?")
		args = append(args, "%"+query+"%")
	}
	if program != "" {
		conds = append(conds, "(program_id LIKE ? OR program_name LIKE ?)")
		args = append(args, "%"+program+"%", "%"+program+"%")
	}
	if severity != "" {
		conds = append(conds, "LOWER(severity) = LOWER(?)")
		args = append(args, severity)
	}
	if status != "" {
		conds = append(conds, "LOWER(status) = LOWER(?)")
		args = append(args, status)
	}
	where := "1=1"
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}
	args = append(args, limit)

	rows, err := personalDB.Query(
		fmt.Sprintf(`SELECT id, title, status, severity, vuln_type, program_name, asset, bounty, currency, created_at
		 FROM intigriti_submissions WHERE %s ORDER BY bounty DESC, created_at DESC LIMIT ?`, where),
		args...,
	)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	totalBounty := 0.0
	for rows.Next() {
		var id, title, st, sev, vulnType, progName, asset, currency, createdAt string
		var bounty float64
		rows.Scan(&id, &title, &st, &sev, &vulnType, &progName, &asset, &bounty, &currency, &createdAt)
		totalBounty += bounty
		bountyStr := ""
		if bounty > 0 {
			bountyStr = fmt.Sprintf(" — %.0f %s", bounty, currency)
		}
		assetStr := ""
		if asset != "" {
			assetStr = fmt.Sprintf(" on `%s`", asset)
		}
		lines = append(lines, fmt.Sprintf("- [%s/%s] **%s** — %s — %s%s%s%s",
			sev, st, title, progName, vulnType, assetStr, bountyStr,
			fmt.Sprintf(" (%s)", createdAt[:10])))
	}

	if len(lines) == 0 {
		return mcp.NewToolResultText("No submissions found. Run intigriti_fetch_submissions first."), nil
	}
	header := fmt.Sprintf("Found %d submissions (total bounties: %.0f):\n\n", len(lines), totalBounty)
	return mcp.NewToolResultText(header + strings.Join(lines, "\n")), nil
}
