package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerWriteTools(s *server.MCPServer, client *H1Client) {
	s.AddTool(mcp.NewTool("add_comment",
		mcp.WithDescription("Add a comment to one of your reports — respond to triage, provide extra info, or follow up."),
		mcp.WithString("report_id", mcp.Required(), mcp.Description("Report ID")),
		mcp.WithString("message", mcp.Required(), mcp.Description("Your comment text")),
		mcp.WithString("internal", mcp.Description("'true' to post as internal comment (team-only), default false")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["report_id"].(string)
		msg, _ := req.GetArguments()["message"].(string)
		internal, _ := req.GetArguments()["internal"].(string)
		return addCommentHandler(ctx, client, id, msg, internal == "true")
	})

	s.AddTool(mcp.NewTool("close_report",
		mcp.WithDescription("Close/withdraw one of your own reports. Use when a report is invalid, a duplicate, or you want to retract it."),
		mcp.WithString("report_id", mcp.Required(), mcp.Description("Report ID to close")),
		mcp.WithString("reason", mcp.Required(), mcp.Description("Reason: not-applicable | duplicate | spam | na")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["report_id"].(string)
		reason, _ := req.GetArguments()["reason"].(string)
		return closeReportHandler(ctx, client, id, reason)
	})

	s.AddTool(mcp.NewTool("submit_report",
		mcp.WithDescription("Submit a vulnerability report to a HackerOne program. ALWAYS review the full report before calling this — submissions are not easily retracted."),
		mcp.WithString("program_handle", mcp.Required(), mcp.Description("Target program handle")),
		mcp.WithString("title", mcp.Required(), mcp.Description("Report title")),
		mcp.WithString("vulnerability_information", mcp.Required(), mcp.Description("Full write-up: description, reproduction steps, impact")),
		mcp.WithString("severity", mcp.Required(), mcp.Description("none | low | medium | high | critical")),
		mcp.WithString("weakness_id", mcp.Description("CWE ID if known e.g. 'CWE-79'")),
		mcp.WithString("asset_identifier", mcp.Description("In-scope asset the bug was found on")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handle, _ := req.GetArguments()["program_handle"].(string)
		title, _ := req.GetArguments()["title"].(string)
		vulnInfo, _ := req.GetArguments()["vulnerability_information"].(string)
		severity, _ := req.GetArguments()["severity"].(string)
		weaknessID, _ := req.GetArguments()["weakness_id"].(string)
		asset, _ := req.GetArguments()["asset_identifier"].(string)
		return submitReportHandler(ctx, client, handle, title, vulnInfo, severity, weaknessID, asset)
	})
}

func addCommentHandler(ctx context.Context, client *H1Client, reportID, message string, internal bool) (*mcp.CallToolResult, error) {
	if reportID == "" || message == "" {
		return mcp.NewToolResultText("report_id and message are required."), nil
	}

	payload := map[string]any{
		"data": map[string]any{
			"type": "activity-comment",
			"attributes": map[string]any{
				"message":  message,
				"internal": internal,
			},
		},
	}

	result, err := client.post(ctx, "/hackers/reports/"+reportID+"/activities", payload)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	data, _ := result["data"].(map[string]any)
	a := attrs(data)
	return mcp.NewToolResultText(fmt.Sprintf(
		"Comment added to report #%s at %s.", reportID, str(a, "created_at"),
	)), nil
}

func closeReportHandler(ctx context.Context, client *H1Client, reportID, reason string) (*mcp.CallToolResult, error) {
	if reportID == "" {
		return mcp.NewToolResultText("report_id is required."), nil
	}

	validReasons := map[string]bool{
		"not-applicable": true, "duplicate": true, "spam": true, "na": true,
	}
	if !validReasons[strings.ToLower(reason)] {
		return mcp.NewToolResultText("reason must be one of: not-applicable | duplicate | spam | na"), nil
	}

	payload := map[string]any{
		"data": map[string]any{
			"type": "state-change",
			"attributes": map[string]any{
				"substate": reason,
			},
		},
	}

	_, err := client.post(ctx, "/hackers/reports/"+reportID+"/state_changes", payload)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Report #%s closed with reason: %s.", reportID, reason)), nil
}

func submitReportHandler(
	ctx context.Context,
	client *H1Client,
	handle, title, vulnInfo, severity, weaknessID, asset string,
) (*mcp.CallToolResult, error) {
	if handle == "" || title == "" || vulnInfo == "" || severity == "" {
		return mcp.NewToolResultText("program_handle, title, vulnerability_information, and severity are all required."), nil
	}

	validSeverities := map[string]bool{
		"none": true, "low": true, "medium": true, "high": true, "critical": true,
	}
	if !validSeverities[strings.ToLower(severity)] {
		return mcp.NewToolResultText("severity must be: none | low | medium | high | critical"), nil
	}

	// Build report payload
	reportAttrs := map[string]any{
		"title":                    title,
		"vulnerability_information": vulnInfo,
	}

	relationships := map[string]any{
		"program": map[string]any{
			"data": map[string]any{
				"type":       "program",
				"attributes": map[string]any{"handle": handle},
			},
		},
		"severity": map[string]any{
			"data": map[string]any{
				"type":       "severity",
				"attributes": map[string]any{"rating": strings.ToLower(severity)},
			},
		},
	}

	if weaknessID != "" {
		relationships["weakness"] = map[string]any{
			"data": map[string]any{
				"type":       "weakness",
				"attributes": map[string]any{"external_id": weaknessID},
			},
		}
	}

	if asset != "" {
		relationships["structured_scope"] = map[string]any{
			"data": map[string]any{
				"type":       "structured-scope",
				"attributes": map[string]any{"asset_identifier": asset},
			},
		}
	}

	payload := map[string]any{
		"data": map[string]any{
			"type":          "report",
			"attributes":    reportAttrs,
			"relationships": relationships,
		},
	}

	result, err := client.post(ctx, "/hackers/reports", payload)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("Submission failed: %v", err)), nil
	}

	data, _ := result["data"].(map[string]any)
	reportID := str(data, "id")
	a := attrs(data)

	return mcp.NewToolResultText(fmt.Sprintf(
		"Report submitted successfully!\n\n**Report ID:** #%s\n**Title:** %s\n**Program:** %s\n**Severity:** %s\n**State:** %s\n\nView at: https://hackerone.com/reports/%s",
		reportID, str(a, "title"), handle, severity, str(a, "state"), reportID,
	)), nil
}
