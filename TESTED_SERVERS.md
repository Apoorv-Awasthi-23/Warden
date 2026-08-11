# Tested MCP Servers

Short log of MCP servers connected through this proxy: what machine-specific
setup they needed, if any. Add a brief entry when you test a new one.

## Template

## <server name> (`<npm package / command>`)
- **Status:** works out of the box / needed modifications / blocked
- **Problem:** <one-line symptom, if any>
- **Fix:** <one or two lines>
- **Tested on:** <OS/environment specifics, only if machine-specific>
- **Diagnosed with:** Claude Code, <date>

---

## Playwright (`@playwright/mcp`)
- **Status:** needed modifications
- **Problem:** No system Chrome installed; `--executable-path` alone didn't
  work due to a channel-default quirk in `@playwright/mcp`; concurrent proxy
  instances collided over one on-disk browser profile.
- **Fix:** Local `local/playwright-mcp.config.json` (gitignored, template
  in that folder) setting `browserName`, `executablePath`, and
  `isolated: true`; `rules/playwright.yaml` added to block
  `browser_run_code_unsafe` (RCE-equivalent, previously ungated).
- **Tested on:** Linux, no system Chrome, only snap Chromium available, no
  passwordless sudo.
- **Diagnosed with:** Claude Code (Sonnet 5), 2026-08-12.
