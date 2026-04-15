package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerHackTools(s *server.MCPServer, client *H1Client) {
	s.AddTool(mcp.NewTool("hack",
		mcp.WithDescription("Start a hacking session on a program. Fetches live scope, cross-references your history and 3,600+ disclosed reports, identifies untouched assets, and generates a chain-focused attack briefing."),
		mcp.WithString("handle", mcp.Required(), mcp.Description("Program handle e.g. 'google', 'twitter'")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handle, _ := req.GetArguments()["handle"].(string)
		return hackHandler(ctx, client, handle)
	})

	s.AddTool(mcp.NewTool("get_chain_suggestions",
		mcp.WithDescription("Analyze disclosed reports for a program and suggest vulnerability chains — combinations of bugs that together produce a higher-impact exploit than any individual finding."),
		mcp.WithString("handle", mcp.Required(), mcp.Description("Program handle")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handle, _ := req.GetArguments()["handle"].(string)
		return chainSuggestionsHandler(handle)
	})
}

// --- hack() ---

func hackHandler(ctx context.Context, client *H1Client, handle string) (*mcp.CallToolResult, error) {
	if handle == "" {
		return mcp.NewToolResultText("handle is required"), nil
	}

	// 1. Fetch fresh scope from API
	scopeRaw, err := client.fetchAllPages(ctx, "/hackers/programs/"+handle+"/structured_scopes", nil)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("Failed to fetch scope: %v", err)), nil
	}

	personalDB.Exec("DELETE FROM scopes WHERE program_handle = ?", handle)
	for _, s := range scopeRaw {
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

	// 2. Load scopes
	type scope struct {
		identifier, assetType, maxSev, instruction string
		bountyEligible                             bool
	}
	var bountyScopes, noBountyScopes []scope

	rows, _ := personalDB.Query(`
		SELECT asset_identifier, asset_type, max_severity, instruction, eligible_for_bounty
		FROM scopes WHERE program_handle = ? AND eligible_for_submission = 1`, handle)
	defer rows.Close()
	var allScopes []scope
	for rows.Next() {
		var s scope
		var be int
		rows.Scan(&s.identifier, &s.assetType, &s.maxSev, &s.instruction, &be)
		s.bountyEligible = be == 1
		allScopes = append(allScopes, s)
		if s.bountyEligible {
			bountyScopes = append(bountyScopes, s)
		} else {
			noBountyScopes = append(noBountyScopes, s)
		}
	}

	// 3. Your past reports on this program (ALL states, not just rewarded)
	type report struct {
		id, title, state, weakness, cwe, sev, asset string
		bounty                                      float64
	}
	var myReports []report
	myRows, _ := personalDB.Query(`
		SELECT id, title, state, weakness_name, weakness_cwe,
			severity_rating, bounty_amount, asset_identifier
		FROM reports WHERE program_handle = ? ORDER BY bounty_amount DESC`, handle)
	defer myRows.Close()
	for myRows.Next() {
		var r report
		myRows.Scan(&r.id, &r.title, &r.state, &r.weakness, &r.cwe, &r.sev, &r.bounty, &r.asset)
		myReports = append(myReports, r)
	}

	// 4. Untouched scope — FIXED: match against asset_identifier field, not just title
	testedAssets := map[string]bool{}
	for _, r := range myReports {
		if r.asset != "" {
			testedAssets[strings.ToLower(r.asset)] = true
		}
	}
	var untouched []scope
	for _, s := range bountyScopes {
		assetLow := strings.ToLower(s.identifier)
		if !testedAssets[assetLow] {
			// Also check if any report's asset is a subdomain of a wildcard scope
			covered := false
			for tested := range testedAssets {
				if wildcardCovers(assetLow, tested) {
					covered = true
					break
				}
			}
			if !covered {
				untouched = append(untouched, s)
			}
		}
	}

	// 5. Weaknesses you've found here before
	myWeaknesses := map[string]int{}
	for _, r := range myReports {
		if r.weakness != "" {
			myWeaknesses[r.weakness]++
		}
	}

	// 6. Weaknesses rewarded on other programs but not yet here
	type suggestion struct {
		name      string
		programs  []string
	}
	allMyReports, _ := personalDB.Query(`
		SELECT weakness_name, program_handle FROM reports
		WHERE weakness_name != '' AND program_handle != ?`, handle)
	defer allMyReports.Close()
	globalWeaknesses := map[string]map[string]bool{}
	for allMyReports.Next() {
		var wname, prog string
		allMyReports.Scan(&wname, &prog)
		if _, ok := globalWeaknesses[wname]; !ok {
			globalWeaknesses[wname] = map[string]bool{}
		}
		globalWeaknesses[wname][prog] = true
	}
	var suggestions []suggestion
	for wname, progs := range globalWeaknesses {
		if myWeaknesses[wname] == 0 {
			var progList []string
			for p := range progs {
				progList = append(progList, p)
			}
			sort.Strings(progList)
			suggestions = append(suggestions, suggestion{wname, progList})
		}
	}
	sort.Slice(suggestions, func(i, j int) bool {
		return len(suggestions[i].programs) > len(suggestions[j].programs)
	})

	// 7. Community disclosed reports for this program
	type disReport struct {
		id      int
		title   string
		weak    string
		asset   string
		bounty  float64
	}
	var disclosed []disReport
	disRows, _ := disclosedDB.Query(`
		SELECT id, title, weakness_name, asset_identifier, bounty_amount
		FROM disclosed_reports WHERE program_handle = ?
		ORDER BY bounty_amount DESC, id DESC LIMIT 25`, handle)
	defer disRows.Close()
	disWeaknesses := map[string]int{}
	for disRows.Next() {
		var d disReport
		disRows.Scan(&d.id, &d.title, &d.weak, &d.asset, &d.bounty)
		disclosed = append(disclosed, d)
		if d.weak != "" {
			disWeaknesses[d.weak]++
		}
	}

	// 8. Build chain suggestions from community data
	chains := buildChainSuggestions(disWeaknesses, myWeaknesses)

	// 9. Weaknesses in community reports but NOT in your history = opportunity
	var communityGaps []string
	for weak, cnt := range disWeaknesses {
		if myWeaknesses[weak] == 0 {
			communityGaps = append(communityGaps, fmt.Sprintf("%s (%dx in disclosed reports)", weak, cnt))
		}
	}
	sort.Strings(communityGaps)

	// --- Build briefing ---
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Hack Session: %s\n\n", handle))

	// Scope
	sb.WriteString("## In-Scope Assets (Bounty Eligible)\n")
	if len(bountyScopes) == 0 {
		sb.WriteString("No bounty-eligible scope found.\n")
	}
	for _, s := range bountyScopes {
		line := fmt.Sprintf("- `%s` (%s) [max: %s]", s.identifier, s.assetType, s.maxSev)
		if s.instruction != "" {
			line += "\n  > " + s.instruction
		}
		sb.WriteString(line + "\n")
	}

	if len(noBountyScopes) > 0 {
		sb.WriteString("\n### In-Scope (No Bounty — useful for recon pivot)\n")
		for _, s := range noBountyScopes {
			sb.WriteString(fmt.Sprintf("- `%s` (%s)\n", s.identifier, s.assetType))
		}
	}

	// Your past findings
	totalBounty := 0.0
	for _, r := range myReports {
		totalBounty += r.bounty
	}
	sb.WriteString(fmt.Sprintf("\n## Your History Here (%d reports", len(myReports)))
	if totalBounty > 0 {
		sb.WriteString(fmt.Sprintf(", $%.0f earned", totalBounty))
	}
	sb.WriteString(")\n")
	if len(myReports) == 0 {
		sb.WriteString("No reports on this program yet — fresh territory.\n")
	}
	for _, r := range myReports {
		bountyStr := ""
		if r.bounty > 0 {
			bountyStr = fmt.Sprintf(" — $%.0f", r.bounty)
		}
		sb.WriteString(fmt.Sprintf("- [%s/%s] #%s %s — %s%s\n",
			r.sev, r.state, r.id, r.title, r.weakness, bountyStr))
	}

	// Untouched scope
	sb.WriteString(fmt.Sprintf("\n## Untouched Assets (%d)\n", len(untouched)))
	sb.WriteString("Bounty-eligible assets with zero findings from you:\n")
	if len(untouched) == 0 {
		sb.WriteString("All known bounty-eligible assets have been touched.\n")
	}
	for _, s := range untouched {
		sb.WriteString(fmt.Sprintf("- `%s` (%s) [max: %s]\n", s.identifier, s.assetType, s.maxSev))
	}

	// Community gaps (bugs found by others, not by you)
	if len(communityGaps) > 0 {
		sb.WriteString("\n## Community Bugs You Haven't Found Here\n")
		sb.WriteString("These weakness types appear in disclosed reports but not in your history:\n")
		for _, g := range communityGaps {
			sb.WriteString("- " + g + "\n")
		}
	}

	// Chain suggestions — our primary goal
	if len(chains) > 0 {
		sb.WriteString("\n## Chain Opportunities\n")
		sb.WriteString("Vulnerability combinations found in disclosed reports that chain to higher impact:\n\n")
		for _, c := range chains {
			sb.WriteString(fmt.Sprintf("### %s\n%s\n\n", c.title, c.description))
		}
	}

	// Your suggested vectors from personal history
	if len(suggestions) > 0 {
		sb.WriteString("\n## Your Proven Vectors (worked elsewhere, not found here yet)\n")
		for _, s := range suggestions[:min(len(suggestions), 8)] {
			sb.WriteString(fmt.Sprintf("- **%s** — rewarded on: %s\n",
				s.name, strings.Join(s.programs[:min(len(s.programs), 4)], ", ")))
		}
	}

	// Community disclosed reports
	if len(disclosed) > 0 {
		var totalDis int
		disclosedDB.QueryRow("SELECT COUNT(*) FROM disclosed_reports WHERE program_handle = ?", handle).Scan(&totalDis)
		sb.WriteString(fmt.Sprintf("\n## Public Disclosed Reports (%d total)\n", totalDis))
		sb.WriteString("What the community found here (top by bounty):\n")
		for _, d := range disclosed {
			bountyStr := ""
			if d.bounty > 0 {
				bountyStr = fmt.Sprintf(" — $%.0f", d.bounty)
			}
			assetStr := ""
			if d.asset != "" {
				assetStr = fmt.Sprintf(" on `%s`", d.asset)
			}
			sb.WriteString(fmt.Sprintf("- #%d %s — %s%s%s\n", d.id, d.title, d.weak, assetStr, bountyStr))
		}
		if totalDis > 25 {
			sb.WriteString(fmt.Sprintf("_...and %d more. Use search_disclosed_reports(program='%s') for full list._\n", totalDis-25, handle))
		}
	}

	// Inject our custom hunt instructions
	sb.WriteString("\n---\n\n")
	sb.WriteString(huntInstructions(handle))

	return mcp.NewToolResultText(sb.String()), nil
}

// --- Chain Intelligence ---

type chainSuggestion struct {
	title       string
	description string
}

// buildChainSuggestions takes weakness frequency maps and returns chaining opportunities.
func buildChainSuggestions(disWeaknesses, myWeaknesses map[string]int) []chainSuggestion {
	// Known high-value chains in bug bounty
	type chainRule struct {
		a, b        string // weakness types that co-occur
		title       string
		description string
	}

	rules := []chainRule{
		{
			"Cross-Site Scripting (XSS)", "Cross-Site Request Forgery (CSRF)",
			"Self-XSS → Victim-Exploitable XSS via CSRF",
			"Self-XSS alone is informational. If CSRF exists anywhere in the app, chain them: CSRF forces the victim to trigger the XSS context, making it exploitable by any attacker. Impact: High.",
		},
		{
			"Open Redirect", "Improper Authentication",
			"Open Redirect → OAuth Token Theft → Account Takeover",
			"If the app uses OAuth, an open redirect in the redirect_uri can steal the auth code/token. Chain: craft OAuth URL with redirect to your open redirect → steal token → account takeover. Impact: Critical.",
		},
		{
			"Server-Side Request Forgery (SSRF)", "Improper Authentication",
			"SSRF → Internal Service Access → Credential Theft",
			"SSRF reaching internal services (metadata, internal APIs) bypasses network-level auth. Escalate to cloud metadata (169.254.169.254) for IAM keys or internal admin panels. Impact: Critical.",
		},
		{
			"Cross-Site Scripting (XSS)", "Improper Authentication",
			"XSS → Session Hijack → Account Takeover",
			"Stored/reflected XSS that exfils session cookies or fires in an authenticated context leads to full account takeover. Demonstrate with a PoC that sends document.cookie to an interactsh callback. Impact: Critical.",
		},
		{
			"Insecure Direct Object References (IDOR)", "Privilege Escalation",
			"IDOR → Privilege Escalation → Admin Access",
			"IDOR giving access to another user's data + a privilege escalation path (role parameter, JWT claim manipulation) can escalate to admin-level access. Impact: Critical.",
		},
		{
			"Information Disclosure", "Cross-Site Scripting (XSS)",
			"Info Disclosure → XSS Token Theft → Account Takeover",
			"Leaked CSRF tokens, API keys, or internal paths combined with XSS create a reliable account takeover chain. Info disclosure alone is low — in a chain it's critical. Impact: High/Critical.",
		},
		{
			"Improper Access Control", "Cross-Site Request Forgery (CSRF)",
			"CSRF → Unauthorized State Change",
			"CSRF on a privileged action (password change, email update, fund transfer) with missing or bypassable token is directly exploitable. No additional chaining needed — submit with PoC. Impact: High.",
		},
		{
			"Path Traversal", "Information Disclosure",
			"Path Traversal → Sensitive File Read → Credential Exposure",
			"Path traversal reaching /etc/passwd, .env, config files, or SSH keys can expose credentials for further compromise. Chain to SSRF or RCE if internal services are reachable. Impact: High/Critical.",
		},
		{
			"Subdomain Takeover", "Cross-Site Scripting (XSS)",
			"Subdomain Takeover → Cookie Theft → Account Takeover",
			"A taken-over subdomain under *.target.com can set cookies for the parent domain. Combine with an XSS payload served from the taken-over subdomain to steal session cookies. Impact: Critical.",
		},
		{
			"Cross-Origin Resource Sharing (CORS)", "Information Disclosure",
			"CORS Misconfiguration → Cross-Origin Data Theft",
			"Permissive CORS (null origin, arbitrary origin reflection) on a sensitive API endpoint allows a malicious page to read authenticated responses. PoC: iframe + fetch from attacker.com. Impact: High.",
		},
		{
			"XML External Entity (XXE) Injection", "Server-Side Request Forgery (SSRF)",
			"XXE → SSRF → Internal Network Access",
			"XXE with SYSTEM entity can trigger SSRF via the XML parser. Escalate to cloud metadata or internal service enumeration. Use interactsh for blind XXE confirmation first. Impact: Critical.",
		},
	}

	var results []chainSuggestion
	for _, rule := range rules {
		aPresent := disWeaknesses[rule.a] > 0 || myWeaknesses[rule.a] > 0
		bPresent := disWeaknesses[rule.b] > 0 || myWeaknesses[rule.b] > 0
		if aPresent && bPresent {
			results = append(results, chainSuggestion{
				title:       rule.title,
				description: fmt.Sprintf("%s\n\n_Evidence: %s found %dx, %s found %dx in program reports._", rule.description, rule.a, disWeaknesses[rule.a]+myWeaknesses[rule.a], rule.b, disWeaknesses[rule.b]+myWeaknesses[rule.b]),
			})
		}
	}
	return results
}

// chainSuggestionsHandler is the dedicated chain analysis tool.
func chainSuggestionsHandler(handle string) (*mcp.CallToolResult, error) {
	disWeaknesses := map[string]int{}
	disRows, _ := disclosedDB.Query(`
		SELECT weakness_name, COUNT(*) FROM disclosed_reports
		WHERE program_handle = ? AND weakness_name != ''
		GROUP BY weakness_name`, handle)
	defer disRows.Close()
	for disRows.Next() {
		var w string
		var c int
		disRows.Scan(&w, &c)
		disWeaknesses[w] = c
	}

	myWeaknesses := map[string]int{}
	myRows, _ := personalDB.Query(`
		SELECT weakness_name, COUNT(*) FROM reports
		WHERE program_handle = ? AND weakness_name != ''
		GROUP BY weakness_name`, handle)
	defer myRows.Close()
	for myRows.Next() {
		var w string
		var c int
		myRows.Scan(&w, &c)
		myWeaknesses[w] = c
	}

	chains := buildChainSuggestions(disWeaknesses, myWeaknesses)
	if len(chains) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf(
			"No chain opportunities identified for '%s' based on current data.\n\nRun refresh_disclosed_reports to update the intelligence database.", handle,
		)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Chain Opportunities for %s (%d identified)\n\n", handle, len(chains)))
	for i, c := range chains {
		sb.WriteString(fmt.Sprintf("## %d. %s\n%s\n\n", i+1, c.title, c.description))
	}
	sb.WriteString("\n**Remember:** Never stop at the first bug. Document in Caido Findings → chase the chain → report the full impact.")

	return mcp.NewToolResultText(sb.String()), nil
}

// wildcardCovers checks if a wildcard scope like *.target.com covers a specific asset.
func wildcardCovers(scope, asset string) bool {
	if !strings.HasPrefix(scope, "*.") {
		return false
	}
	base := scope[2:] // strip "*."
	return strings.HasSuffix(asset, "."+base) || asset == base
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
