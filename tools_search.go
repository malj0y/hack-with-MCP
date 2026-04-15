package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerSearchTools(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("search_reports",
		mcp.WithDescription("Search your personal HackerOne reports stored locally."),
		mcp.WithString("query", mcp.Description("Title keyword search")),
		mcp.WithString("program", mcp.Description("Program handle filter")),
		mcp.WithString("weakness", mcp.Description("Weakness type e.g. 'XSS', 'SSRF'")),
		mcp.WithString("severity", mcp.Description("critical | high | medium | low")),
		mcp.WithString("state", mcp.Description("resolved | triaged | new | informative | not-applicable | duplicate")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return searchReportsHandler(req)
	})

	s.AddTool(mcp.NewTool("search_disclosed_reports",
		mcp.WithDescription("Full-text search across 3,600+ publicly disclosed HackerOne reports. Results ranked by relevance."),
		mcp.WithString("query", mcp.Description("Full-text search across title and write-up")),
		mcp.WithString("program", mcp.Description("Program handle filter")),
		mcp.WithString("weakness", mcp.Description("Weakness type filter e.g. 'SSRF'")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return searchDisclosedHandler(req)
	})

	s.AddTool(mcp.NewTool("search_programs",
		mcp.WithDescription("Search your synced HackerOne programs."),
		mcp.WithString("query", mcp.Description("Handle or name search")),
		mcp.WithString("bounty_only", mcp.Description("'true' to filter bounty programs only")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 20)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return searchProgramsHandler(req)
	})

	s.AddTool(mcp.NewTool("search_scopes",
		mcp.WithDescription("Search in-scope assets across all programs."),
		mcp.WithString("program", mcp.Description("Program handle filter")),
		mcp.WithString("asset", mcp.Description("Asset identifier search")),
		mcp.WithString("bounty_only", mcp.Description("'true' for bounty-eligible only")),
		mcp.WithNumber("limit", mcp.Description("Max results (default 30)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return searchScopesHandler(req)
	})

	s.AddTool(mcp.NewTool("get_report_summary",
		mcp.WithDescription("Summary of your reports grouped by program — counts, total bounties, severity breakdown."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return reportSummaryHandler()
	})

	s.AddTool(mcp.NewTool("analyze_report_patterns",
		mcp.WithDescription("Analyze patterns across all your reports — top weakness types, severity distribution, highest-paying programs."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return analyzePatternHandler()
	})
}

func searchReportsHandler(req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, _ := req.GetArguments()["query"].(string)
	program, _ := req.GetArguments()["program"].(string)
	weakness, _ := req.GetArguments()["weakness"].(string)
	severity, _ := req.GetArguments()["severity"].(string)
	state, _ := req.GetArguments()["state"].(string)
	limit := 20
	if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}

	var conds []string
	var args []any

	if query != "" {
		conds = append(conds, "(title LIKE ? OR vuln_info LIKE ?)")
		args = append(args, "%"+query+"%", "%"+query+"%")
	}
	if program != "" {
		conds = append(conds, "program_handle LIKE ?")
		args = append(args, "%"+program+"%")
	}
	if weakness != "" {
		conds = append(conds, "(weakness_name LIKE ? OR weakness_cwe LIKE ?)")
		args = append(args, "%"+weakness+"%", "%"+weakness+"%")
	}
	if severity != "" {
		conds = append(conds, "severity_rating = ?")
		args = append(args, strings.ToLower(severity))
	}
	if state != "" {
		conds = append(conds, "state = ?")
		args = append(args, state)
	}

	where := "1=1"
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}
	args = append(args, limit)

	rows, err := personalDB.Query(
		fmt.Sprintf(`SELECT id, title, state, program_handle, weakness_name, weakness_cwe,
			severity_rating, bounty_amount, bounty_currency, asset_identifier, vuln_info
		 FROM reports WHERE %s ORDER BY bounty_amount DESC, created_at DESC LIMIT ?`, where),
		args...,
	)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count := 0
	totalBounty := 0.0

	for rows.Next() {
		var id, title, state, prog, weak, cwe, sev, asset, vuln string
		var bounty float64
		var currency string
		rows.Scan(&id, &title, &state, &prog, &weak, &cwe, &sev, &bounty, &currency, &asset, &vuln)

		count++
		totalBounty += bounty
		weakStr := weak
		if cwe != "" {
			weakStr += " (" + cwe + ")"
		}
		bountyStr := fmt.Sprintf("$%.0f %s", bounty, currency)
		lines = append(lines, fmt.Sprintf("- **#%s** [%s/%s] %s — %s — %s — %s",
			id, sev, state, title, prog, weakStr, bountyStr))
		if asset != "" {
			lines = append(lines, fmt.Sprintf("  Asset: `%s`", asset))
		}
		if vuln != "" && len(vuln) > 0 {
			snippet := vuln
			if len(snippet) > 180 {
				snippet = snippet[:180] + "..."
			}
			lines = append(lines, "  > "+strings.ReplaceAll(snippet, "\n", " "))
		}
	}

	if count == 0 {
		return mcp.NewToolResultText("No reports found matching your search."), nil
	}

	header := fmt.Sprintf("Found %d reports (total bounties: $%.0f)\n", count, totalBounty)
	return mcp.NewToolResultText(header + strings.Join(lines, "\n")), nil
}

func searchDisclosedHandler(req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, _ := req.GetArguments()["query"].(string)
	program, _ := req.GetArguments()["program"].(string)
	weakness, _ := req.GetArguments()["weakness"].(string)
	limit := 20
	if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}

	var lines []string
	var count int

	if query != "" {
		// FTS5 search — ORDER BY rank (relevance), not insertion order
		var conds []string
		var args []any
		args = append(args, query)

		if program != "" {
			conds = append(conds, "d.program_handle LIKE ?")
			args = append(args, "%"+program+"%")
		}
		if weakness != "" {
			conds = append(conds, "d.weakness_name LIKE ?")
			args = append(args, "%"+weakness+"%")
		}
		extraWhere := ""
		if len(conds) > 0 {
			extraWhere = " AND " + strings.Join(conds, " AND ")
		}
		args = append(args, limit)

		// Fix from h1-brain: ORDER BY rank (FTS relevance), not d.id
		rows, err := disclosedDB.Query(fmt.Sprintf(`
			SELECT d.id, d.title, d.weakness_name, d.program_handle,
			       d.asset_identifier, d.bounty_amount, fts.rank
			FROM disclosed_fts fts
			JOIN disclosed_reports d ON d.id = fts.rowid
			WHERE disclosed_fts MATCH ?%s
			ORDER BY fts.rank
			LIMIT ?`, extraWhere), args...)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("FTS error: %v", err)), nil
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var title, weak, prog, asset string
			var bounty float64
			var rank float64
			rows.Scan(&id, &title, &weak, &prog, &asset, &bounty, &rank)
			count++
			bountyStr := ""
			if bounty > 0 {
				bountyStr = fmt.Sprintf(" — $%.0f", bounty)
			}
			assetStr := ""
			if asset != "" {
				assetStr = fmt.Sprintf(" on `%s`", asset)
			}
			lines = append(lines, fmt.Sprintf("- **#%d** %s — %s — %s%s%s",
				id, title, prog, weak, assetStr, bountyStr))
		}
	} else {
		// No FTS query — filter by program/weakness
		var conds []string
		var args []any
		if program != "" {
			conds = append(conds, "program_handle LIKE ?")
			args = append(args, "%"+program+"%")
		}
		if weakness != "" {
			conds = append(conds, "weakness_name LIKE ?")
			args = append(args, "%"+weakness+"%")
		}
		where := "1=1"
		if len(conds) > 0 {
			where = strings.Join(conds, " AND ")
		}
		args = append(args, limit)

		rows, err := disclosedDB.Query(fmt.Sprintf(`
			SELECT id, title, weakness_name, program_handle, asset_identifier, bounty_amount
			FROM disclosed_reports WHERE %s
			ORDER BY bounty_amount DESC, id DESC LIMIT ?`, where), args...)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var title, weak, prog, asset string
			var bounty float64
			rows.Scan(&id, &title, &weak, &prog, &asset, &bounty)
			count++
			bountyStr := ""
			if bounty > 0 {
				bountyStr = fmt.Sprintf(" — $%.0f", bounty)
			}
			lines = append(lines, fmt.Sprintf("- **#%d** %s — %s — %s%s", id, title, prog, weak, bountyStr))
		}
	}

	if count == 0 {
		return mcp.NewToolResultText("No disclosed reports found."), nil
	}

	header := fmt.Sprintf("Found %d disclosed reports:\n\n", count)
	lines = append(lines, "\n_Use get_disclosed_report(id) for full write-up._")
	return mcp.NewToolResultText(header + strings.Join(lines, "\n")), nil
}

func searchProgramsHandler(req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		conds = append(conds, "offers_bounties = 1")
	}
	where := "1=1"
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}
	args = append(args, limit)

	rows, err := personalDB.Query(
		fmt.Sprintf("SELECT handle, name, submission_state, offers_bounties FROM programs WHERE %s ORDER BY handle LIMIT ?", where),
		args...,
	)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	for rows.Next() {
		var handle, name, state string
		var bounty int
		rows.Scan(&handle, &name, &state, &bounty)
		tag := ""
		if bounty == 1 {
			tag = " [bounty]"
		}
		lines = append(lines, fmt.Sprintf("- %s — %s%s (%s)", handle, name, tag, state))
	}
	if len(lines) == 0 {
		return mcp.NewToolResultText("No programs found. Run fetch_programs first."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d programs:\n\n%s", len(lines), strings.Join(lines, "\n"))), nil
}

func searchScopesHandler(req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	program, _ := req.GetArguments()["program"].(string)
	asset, _ := req.GetArguments()["asset"].(string)
	bountyOnly, _ := req.GetArguments()["bounty_only"].(string)
	limit := 30
	if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}

	var conds []string
	var args []any
	if program != "" {
		conds = append(conds, "program_handle LIKE ?")
		args = append(args, "%"+program+"%")
	}
	if asset != "" {
		conds = append(conds, "asset_identifier LIKE ?")
		args = append(args, "%"+asset+"%")
	}
	if bountyOnly == "true" {
		conds = append(conds, "eligible_for_bounty = 1")
	}
	where := "1=1"
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}
	args = append(args, limit)

	rows, err := personalDB.Query(
		fmt.Sprintf(`SELECT asset_identifier, asset_type, program_handle,
			eligible_for_bounty, max_severity, instruction
		 FROM scopes WHERE %s ORDER BY program_handle, asset_identifier LIMIT ?`, where),
		args...,
	)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	for rows.Next() {
		var asset, atype, prog, maxSev, instr string
		var bounty int
		rows.Scan(&asset, &atype, &prog, &bounty, &maxSev, &instr)
		tag := ""
		if bounty == 1 {
			tag = " [bounty]"
		}
		line := fmt.Sprintf("- `%s` (%s) — %s%s [max: %s]", asset, atype, prog, tag, maxSev)
		if instr != "" {
			line += "\n  > " + instr
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return mcp.NewToolResultText("No scopes found."), nil
	}
	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func reportSummaryHandler() (*mcp.CallToolResult, error) {
	rows, err := personalDB.Query(`
		SELECT program_handle, COUNT(*) as cnt,
			SUM(CASE WHEN bounty_amount > 0 THEN bounty_amount ELSE 0 END) as total,
			COUNT(CASE WHEN severity_rating = 'critical' THEN 1 END) as crit,
			COUNT(CASE WHEN severity_rating = 'high' THEN 1 END) as high
		FROM reports
		GROUP BY program_handle
		ORDER BY total DESC`)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	grandTotal := 0.0
	grandCount := 0

	for rows.Next() {
		var prog string
		var cnt, crit, high int
		var total float64
		rows.Scan(&prog, &cnt, &total, &crit, &high)
		grandTotal += total
		grandCount += cnt
		if prog == "" {
			prog = "unknown"
		}
		lines = append(lines, fmt.Sprintf("- **%s**: %d reports, $%.0f (crit: %d, high: %d)",
			prog, cnt, total, crit, high))
	}

	if len(lines) == 0 {
		return mcp.NewToolResultText("No reports yet. Run fetch_reports first."), nil
	}

	header := fmt.Sprintf("## Report Summary\nTotal: %d reports | $%.0f earned\n\n", grandCount, grandTotal)
	return mcp.NewToolResultText(header + strings.Join(lines, "\n")), nil
}

func analyzePatternHandler() (*mcp.CallToolResult, error) {
	var sb strings.Builder
	sb.WriteString("## Your Report Pattern Analysis\n\n")

	// Top weakness types
	rows, _ := personalDB.Query(`
		SELECT weakness_name, COUNT(*) as cnt, SUM(bounty_amount) as total
		FROM reports WHERE weakness_name != ''
		GROUP BY weakness_name ORDER BY cnt DESC LIMIT 10`)
	defer rows.Close()
	sb.WriteString("### Top Weakness Types\n")
	for rows.Next() {
		var name string
		var cnt int
		var total float64
		rows.Scan(&name, &cnt, &total)
		sb.WriteString(fmt.Sprintf("- %s: %dx, $%.0f total\n", name, cnt, total))
	}

	// Severity distribution
	sb.WriteString("\n### Severity Distribution\n")
	sevRows, _ := personalDB.Query(`
		SELECT severity_rating, COUNT(*) FROM reports
		WHERE severity_rating != ''
		GROUP BY severity_rating ORDER BY COUNT(*) DESC`)
	defer sevRows.Close()
	for sevRows.Next() {
		var sev string
		var cnt int
		sevRows.Scan(&sev, &cnt)
		sb.WriteString(fmt.Sprintf("- %s: %d\n", sev, cnt))
	}

	// Highest-paying programs
	sb.WriteString("\n### Highest Paying Programs\n")
	progRows, _ := personalDB.Query(`
		SELECT program_handle, SUM(bounty_amount) as total, COUNT(*) as cnt
		FROM reports WHERE bounty_amount > 0
		GROUP BY program_handle ORDER BY total DESC LIMIT 5`)
	defer progRows.Close()
	for progRows.Next() {
		var prog string
		var total float64
		var cnt int
		progRows.Scan(&prog, &total, &cnt)
		sb.WriteString(fmt.Sprintf("- %s: $%.0f across %d reports\n", prog, total, cnt))
	}

	return mcp.NewToolResultText(sb.String()), nil
}
