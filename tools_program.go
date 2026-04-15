package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerProgramTools(s *server.MCPServer, client *H1Client) {
	s.AddTool(mcp.NewTool("get_program_details",
		mcp.WithDescription("Get detailed info about a program — policy, response times, average bounties, submission stats."),
		mcp.WithString("handle", mcp.Required(), mcp.Description("Program handle")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handle, _ := req.GetArguments()["handle"].(string)
		return getProgramDetailsHandler(ctx, client, handle)
	})

	s.AddTool(mcp.NewTool("get_program_weaknesses",
		mcp.WithDescription("List the CWE/weakness types accepted by a program. Know what's in scope before hunting."),
		mcp.WithString("handle", mcp.Required(), mcp.Description("Program handle")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handle, _ := req.GetArguments()["handle"].(string)
		return getProgramWeaknessesHandler(ctx, client, handle)
	})

	s.AddTool(mcp.NewTool("get_program_payout_stats",
		mcp.WithDescription("Show average bounty payouts by severity for a program based on publicly disclosed reports. Know what to expect before hunting."),
		mcp.WithString("handle", mcp.Required(), mcp.Description("Program handle")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handle, _ := req.GetArguments()["handle"].(string)
		return getProgramPayoutStatsHandler(handle)
	})

	s.AddTool(mcp.NewTool("get_hacker_profile",
		mcp.WithDescription("Get your HackerOne profile stats — reputation, signal, impact, and rank."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return getHackerProfileHandler(ctx, client)
	})

	s.AddTool(mcp.NewTool("get_earnings",
		mcp.WithDescription("Get your bounty earnings history from HackerOne."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return getEarningsHandler(ctx, client)
	})

	s.AddTool(mcp.NewTool("get_balance",
		mcp.WithDescription("Get your current unpaid bounty balance on HackerOne."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return getBalanceHandler(ctx, client)
	})
}

func getProgramDetailsHandler(ctx context.Context, client *H1Client, handle string) (*mcp.CallToolResult, error) {
	result, err := client.get(ctx, "/hackers/programs/"+handle, nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	data, _ := result["data"].(map[string]any)
	a := attrs(data)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Program: %s (%s)\n\n", str(a, "name"), handle))
	sb.WriteString(fmt.Sprintf("**State:** %s\n", str(a, "submission_state")))
	sb.WriteString(fmt.Sprintf("**Offers Bounties:** %v\n", boolVal(a, "offers_bounties")))

	// Response efficiency
	if re := str(a, "response_efficiency_percentage"); re != "" {
		sb.WriteString(fmt.Sprintf("**Response Efficiency:** %s%%\n", re))
	}

	// Average bounties
	if bl := flt(a, "average_bounty_lower_amount"); bl > 0 {
		bu := flt(a, "average_bounty_upper_amount")
		sb.WriteString(fmt.Sprintf("**Avg Bounty Range:** $%.0f – $%.0f\n", bl, bu))
	}
	if mb := flt(a, "most_recent_critical_bounty_amount"); mb > 0 {
		sb.WriteString(fmt.Sprintf("**Most Recent Critical Bounty:** $%.0f\n", mb))
	}

	// Stats
	if tc := flt(a, "total_bounties_paid_prefix"); tc > 0 {
		sb.WriteString(fmt.Sprintf("**Total Bounties Paid:** $%.0fk+\n", tc))
	}

	// Policy
	if policy := str(a, "policy"); policy != "" {
		sb.WriteString("\n## Policy\n\n")
		if len(policy) > 1000 {
			sb.WriteString(policy[:1000] + "...\n_(truncated — run get_program_details again with a higher limit if needed)_")
		} else {
			sb.WriteString(policy)
		}
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func getProgramWeaknessesHandler(ctx context.Context, client *H1Client, handle string) (*mcp.CallToolResult, error) {
	raw, err := client.fetchAllPages(ctx, "/hackers/programs/"+handle+"/weaknesses", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	if len(raw) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No weaknesses listed for '%s' (program may accept all types).", handle)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Accepted Weaknesses for %s (%d)\n\n", handle, len(raw)))
	for _, w := range raw {
		a := attrs(w)
		name := str(a, "name")
		extID := str(a, "external_id")
		desc := str(a, "description")
		line := fmt.Sprintf("- **%s**", name)
		if extID != "" {
			line += fmt.Sprintf(" (%s)", extID)
		}
		if desc != "" && len(desc) < 120 {
			line += " — " + desc
		}
		sb.WriteString(line + "\n")
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func getProgramPayoutStatsHandler(handle string) (*mcp.CallToolResult, error) {
	// Query disclosed reports for this program grouped by weakness, show avg/max bounty
	rows, err := disclosedDB.Query(`
		SELECT
			weakness_name,
			COUNT(*) as cnt,
			AVG(bounty_amount) as avg_bounty,
			MAX(bounty_amount) as max_bounty,
			MIN(bounty_amount) as min_bounty
		FROM disclosed_reports
		WHERE program_handle = ? AND bounty_amount > 0
		GROUP BY weakness_name
		ORDER BY avg_bounty DESC`, handle)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("DB error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	totalReports := 0
	for rows.Next() {
		var weak string
		var cnt int
		var avg, max, min float64
		rows.Scan(&weak, &cnt, &avg, &max, &min)
		totalReports += cnt
		if weak == "" {
			weak = "unknown"
		}
		lines = append(lines, fmt.Sprintf("- **%s**: %dx | avg $%.0f | range $%.0f–$%.0f",
			weak, cnt, avg, min, max))
	}

	if len(lines) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No payout data found for '%s' in disclosed reports database.", handle)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Payout Stats for %s\nBased on %d disclosed bounty reports\n\n", handle, totalReports))
	sb.WriteString(strings.Join(lines, "\n"))
	sb.WriteString("\n\n_Source: local disclosed reports DB. Run refresh_disclosed_reports to update._")

	return mcp.NewToolResultText(sb.String()), nil
}

func getHackerProfileHandler(ctx context.Context, client *H1Client) (*mcp.CallToolResult, error) {
	result, err := client.get(ctx, "/hackers/me", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	data, _ := result["data"].(map[string]any)
	a := attrs(data)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Hacker Profile: @%s\n\n", str(a, "username")))
	sb.WriteString(fmt.Sprintf("**Reputation:** %.0f\n", flt(a, "reputation")))
	sb.WriteString(fmt.Sprintf("**Signal:** %.2f\n", flt(a, "signal")))
	sb.WriteString(fmt.Sprintf("**Impact:** %.2f\n", flt(a, "impact")))
	sb.WriteString(fmt.Sprintf("**Rank:** %.0f\n", flt(a, "rank")))

	return mcp.NewToolResultText(sb.String()), nil
}

func getEarningsHandler(ctx context.Context, client *H1Client) (*mcp.CallToolResult, error) {
	result, err := client.get(ctx, "/hackers/me/earnings", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	data, _ := result["data"].([]any)
	if len(data) == 0 {
		return mcp.NewToolResultText("No earnings data found."), nil
	}

	var sb strings.Builder
	sb.WriteString("## Earnings History\n\n")
	total := 0.0

	for _, item := range data {
		if m, ok := item.(map[string]any); ok {
			a := attrs(m)
			amount := flt(a, "amount")
			total += amount
			sb.WriteString(fmt.Sprintf("- $%.0f %s — %s — %s\n",
				amount,
				str(a, "currency"),
				str(a, "awarded_at"),
				str(a, "program_handle"),
			))
		}
	}
	sb.WriteString(fmt.Sprintf("\n**Total: $%.0f**", total))

	return mcp.NewToolResultText(sb.String()), nil
}

func getBalanceHandler(ctx context.Context, client *H1Client) (*mcp.CallToolResult, error) {
	result, err := client.get(ctx, "/hackers/me/payments", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("API error: %v", err)), nil
	}

	data, _ := result["data"].([]any)
	if len(data) == 0 {
		return mcp.NewToolResultText("No pending payments."), nil
	}

	var sb strings.Builder
	sb.WriteString("## Pending Payments\n\n")
	total := 0.0

	for _, item := range data {
		if m, ok := item.(map[string]any); ok {
			a := attrs(m)
			amount := flt(a, "amount")
			total += amount
			sb.WriteString(fmt.Sprintf("- $%.0f — %s\n", amount, str(a, "created_at")))
		}
	}
	sb.WriteString(fmt.Sprintf("\n**Unpaid Balance: $%.0f**", total))

	return mcp.NewToolResultText(sb.String()), nil
}
