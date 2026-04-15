package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerReportTools(s *server.MCPServer, client *H1Client) {
	s.AddTool(mcp.NewTool("get_report",
		mcp.WithDescription("Get full details of one of your personal reports including vulnerability write-up."),
		mcp.WithString("report_id", mcp.Required(), mcp.Description("Report ID")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["report_id"].(string)
		return getReportHandler(id)
	})

	s.AddTool(mcp.NewTool("get_report_with_conversation",
		mcp.WithDescription("Get a report plus its full triage conversation thread — comments, triager replies, state changes."),
		mcp.WithString("report_id", mcp.Required(), mcp.Description("Report ID")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["report_id"].(string)
		return getReportConversationHandler(ctx, client, id)
	})

	s.AddTool(mcp.NewTool("get_report_activities",
		mcp.WithDescription("Get the full activity timeline for a report — state changes, bounty awards, comments, triage events."),
		mcp.WithString("report_id", mcp.Required(), mcp.Description("Report ID")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["report_id"].(string)
		return getReportActivitiesHandler(ctx, client, id)
	})

	s.AddTool(mcp.NewTool("get_disclosed_report",
		mcp.WithDescription("Get the full write-up of a publicly disclosed report from the local database."),
		mcp.WithNumber("report_id", mcp.Required(), mcp.Description("Disclosed report ID")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := int(req.GetArguments()["report_id"].(float64))
		return getDisclosedReportHandler(id)
	})

	s.AddTool(mcp.NewTool("fetch_attachment",
		mcp.WithDescription("Get fresh download URLs for attachments on one of your reports (URLs expire in ~1 hour)."),
		mcp.WithString("report_id", mcp.Required(), mcp.Description("Report ID")),
		mcp.WithString("attachment_id", mcp.Description("Specific attachment ID, or omit for all")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rid, _ := req.GetArguments()["report_id"].(string)
		aid, _ := req.GetArguments()["attachment_id"].(string)
		return fetchAttachmentHandler(ctx, client, rid, aid)
	})
}

func getReportHandler(id string) (*mcp.CallToolResult, error) {
	row := personalDB.QueryRow(`
		SELECT id, title, state, program_handle, weakness_name, weakness_cwe,
			severity_rating, severity_score, bounty_amount, bounty_currency,
			created_at, bounty_awarded_at, disclosed_at, asset_identifier, vuln_info
		FROM reports WHERE id = ?`, id)

	var rid, title, state, prog, weak, cwe, sev, currency, createdAt, awardedAt, disclosedAt, asset, vuln string
	var score, bounty float64
	err := row.Scan(&rid, &title, &state, &prog, &weak, &cwe, &sev, &score, &bounty, &currency,
		&createdAt, &awardedAt, &disclosedAt, &asset, &vuln)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("Report #%s not found. Run fetch_reports first.", id)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Report #%s: %s\n\n", rid, title))
	sb.WriteString(fmt.Sprintf("**Program:** %s\n", prog))
	sb.WriteString(fmt.Sprintf("**State:** %s\n", state))
	if sev != "" {
		sb.WriteString(fmt.Sprintf("**Severity:** %s (%.1f)\n", sev, score))
	}
	if weak != "" {
		sb.WriteString(fmt.Sprintf("**Weakness:** %s", weak))
		if cwe != "" {
			sb.WriteString(" (" + cwe + ")")
		}
		sb.WriteString("\n")
	}
	if bounty > 0 {
		sb.WriteString(fmt.Sprintf("**Bounty:** $%.0f %s\n", bounty, currency))
	}
	if asset != "" {
		sb.WriteString(fmt.Sprintf("**Asset:** `%s`\n", asset))
	}
	sb.WriteString(fmt.Sprintf("**Created:** %s\n", createdAt))
	if awardedAt != "" {
		sb.WriteString(fmt.Sprintf("**Bounty awarded:** %s\n", awardedAt))
	}
	if disclosedAt != "" {
		sb.WriteString(fmt.Sprintf("**Disclosed:** %s\n", disclosedAt))
	}
	sb.WriteString("\n## Vulnerability Details\n\n")
	if vuln != "" {
		sb.WriteString(vuln)
	} else {
		sb.WriteString("_No vulnerability details stored. Run fetch_reports to sync._")
	}

	// Attachments from local DB
	attRows, _ := personalDB.Query(
		"SELECT id, file_name, content_type, file_size FROM attachments WHERE report_id = ?", id)
	defer attRows.Close()
	var attLines []string
	for attRows.Next() {
		var aid, fname, ctype string
		var size int64
		attRows.Scan(&aid, &fname, &ctype, &size)
		attLines = append(attLines, fmt.Sprintf("- %s (%s, %.0f KB) — id: %s", fname, ctype, float64(size)/1024, aid))
	}
	if len(attLines) > 0 {
		sb.WriteString("\n\n## Attachments\n")
		sb.WriteString(strings.Join(attLines, "\n"))
		sb.WriteString("\n_Use fetch_attachment to get download URLs._")
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func getReportConversationHandler(ctx context.Context, client *H1Client, id string) (*mcp.CallToolResult, error) {
	result, err := client.get(ctx, "/hackers/reports/"+id, nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	data, _ := result["data"].(map[string]any)
	a := attrs(data)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Report #%s: %s\n\n", id, str(a, "title")))
	sb.WriteString(fmt.Sprintf("**State:** %s | **Created:** %s\n\n", str(a, "state"), str(a, "created_at")))
	sb.WriteString("## Triage Conversation\n\n")

	// Activities contain the conversation thread
	actList := relDataList(data, "activities")
	if len(actList) == 0 {
		sb.WriteString("No conversation thread available.")
	}
	for _, act := range actList {
		am, ok := act.(map[string]any)
		if !ok {
			continue
		}
		aa := attrs(am)
		actType := str(am, "type")
		msg := str(aa, "message")
		createdAt := str(aa, "created_at")

		// Get actor name
		actorData := relData(am, "actor")
		actorAttrs := attrs(actorData)
		actor := str(actorAttrs, "username")
		if actor == "" {
			actor = str(actorAttrs, "name")
		}
		if actor == "" {
			actor = "system"
		}

		sb.WriteString(fmt.Sprintf("**[%s] %s** (%s)\n", actType, actor, createdAt))
		if msg != "" {
			sb.WriteString(msg + "\n")
		}
		sb.WriteString("\n---\n\n")
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func getReportActivitiesHandler(ctx context.Context, client *H1Client, id string) (*mcp.CallToolResult, error) {
	result, err := client.get(ctx, "/hackers/reports/"+id+"/activities", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	data, _ := result["data"].([]any)
	if len(data) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No activities found for report #%s.", id)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Activity Timeline — Report #%s\n\n", id))

	for _, item := range data {
		am, ok := item.(map[string]any)
		if !ok {
			continue
		}
		aa := attrs(am)
		actType := str(am, "type")
		createdAt := str(aa, "created_at")
		msg := str(aa, "message")

		sb.WriteString(fmt.Sprintf("**%s** — %s\n", actType, createdAt))
		if msg != "" {
			sb.WriteString("> " + strings.ReplaceAll(msg, "\n", "\n> ") + "\n")
		}
		sb.WriteString("\n")
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func getDisclosedReportHandler(id int) (*mcp.CallToolResult, error) {
	row := disclosedDB.QueryRow(`
		SELECT id, title, vuln_info, weakness_name, program_handle,
			asset_identifier, asset_type, bounty_amount
		FROM disclosed_reports WHERE id = ?`, id)

	var rid int
	var title, vuln, weak, prog, asset, atype string
	var bounty float64
	err := row.Scan(&rid, &title, &vuln, &weak, &prog, &asset, &atype, &bounty)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("Disclosed report #%d not found.", id)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Disclosed Report #%d: %s\n\n", rid, title))
	sb.WriteString(fmt.Sprintf("**Program:** %s\n", prog))
	sb.WriteString(fmt.Sprintf("**Weakness:** %s\n", weak))
	if bounty > 0 {
		sb.WriteString(fmt.Sprintf("**Bounty:** $%.0f\n", bounty))
	}
	if asset != "" {
		sb.WriteString(fmt.Sprintf("**Asset:** `%s` (%s)\n", asset, atype))
	}
	sb.WriteString("\n## Write-up\n\n")
	if vuln != "" {
		sb.WriteString(vuln)
	} else {
		sb.WriteString("_No write-up available._")
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func fetchAttachmentHandler(ctx context.Context, client *H1Client, reportID, attachmentID string) (*mcp.CallToolResult, error) {
	result, err := client.get(ctx, "/hackers/reports/"+reportID, nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}
	data, _ := result["data"].(map[string]any)
	attachments := relDataList(data, "attachments")

	if len(attachments) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No attachments on report #%s.", reportID)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Attachments for Report #%s\n\n", reportID))

	for _, att := range attachments {
		am, ok := att.(map[string]any)
		if !ok {
			continue
		}
		if attachmentID != "" && str(am, "id") != attachmentID {
			continue
		}
		aa := attrs(am)
		size := fmt.Sprintf("%.0f KB", flt(aa, "file_size")/1024)
		sb.WriteString(fmt.Sprintf("### %s (%s, %s)\n", str(aa, "file_name"), str(aa, "content_type"), size))
		sb.WriteString(fmt.Sprintf("**Download URL** (expires ~1 hour):\n%s\n\n", str(aa, "expiring_url")))
	}

	return mcp.NewToolResultText(sb.String()), nil
}
