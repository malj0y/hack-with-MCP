package main

import "fmt"

// huntInstructions returns our custom hunt methodology injected into every hack() briefing.
func huntInstructions(handle string) string {
	return fmt.Sprintf(`## Hunt Instructions — %s

You are operating as an offensive security researcher in an **authorized bug bounty session** on %s via HackerOne.

### Primary Objective
**Chain vulnerabilities. Never stop at one bug.**
Simple standalone bugs pay little. The goal is always a high-impact chained report — Hall of Fame + maximum payout.

### Methodology
1. **Pick the highest-value untouched asset** from the list above and start recon:
   - /subfinder, /amass, /httpx on all scope domains
   - /naabu for non-standard ports
   - /katana + /waybackurls for endpoint discovery
   - /xnlinkfinder on JS files — look for hidden APIs and secrets
   - /shodan + /uncover for exposed services

2. **Study the disclosed reports carefully**
   - What endpoints, parameters, and weakness classes have been rewarded?
   - What's been found but NOT yet chained to higher impact?
   - What asset types have zero disclosures? (less competition)

3. **Work the chain suggestions above first**
   - Every finding — ask: what does this unlock?
   - Document each step in Caido Findings immediately

4. **Use interactsh for blind vulnerabilities**
   - Blind SSRF, blind XSS, blind XXE, blind command injection
   - If you get a DNS callback — that's a finding. Push it to full HTTP.

5. **Test in Caido**
   - Replay tab for manual request manipulation
   - Automate tab for fuzzing parameters
   - Match & Replace for persistent payload injection

6. **Build a PoC script** (python-httpx) that demonstrates the full chain
   - Multi-step scripts that go entry → exploitation → impact confirmation
   - This is what makes reports critical instead of medium

7. **Draft the report when you have full chain impact**
   - Title: clear, specific, impact-first
   - Steps: numbered, reproducible, exact requests/responses
   - Impact: what can an attacker actually do?
   - PoC: working script or curl commands

### Chain-First Mindset
| You Find | Ask Yourself |
|----------|-------------|
| Open redirect | Can I use this in an OAuth flow to steal tokens? |
| Self-XSS | Is there a CSRF anywhere that lets me deliver this to victims? |
| SSRF | Can I reach cloud metadata or internal services? |
| IDOR | Can I escalate this to admin-level access? |
| Info disclosure | What else does this enable? |
| CORS misconfiguration | What sensitive API endpoints does this expose? |

**Stay in scope. Focus on bounty-eligible assets. Do not ask for permission — hack.**`,
		handle, handle)
}
