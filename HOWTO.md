# Snyk MCP Server Setup Guide

## Prerequisites

- Snyk account with API token ([get here](https://app.snyk.io/account))
- Snyk CLI: `npm install -g snyk`
- Node.js 18+

## Installation

1. **Install and build:**
   ```bash
   npm install
   npm run build
   ```

2. **Get Snyk credentials:**
   - API Token: Visit [app.snyk.io/account](https://app.snyk.io/account)
   - Organization ID: Check your Snyk org settings (format: `john.doe`)

## Configuration

Add to your `~/.claude/.mcp.json`:

```json
{
  "mcpServers": {
    "snyk": {
      "command": "node",
      "args": ["/absolute/path/to/snyk-mcp-server/build/index.js"],
      "env": {
        "SNYK_TOKEN": "your-snyk-token-here",
        "SNYK_ORG_ID": "your.organization.name"
      }
    }
  }
}
```

**Replace:**
- Update the absolute path to your server location
- Add your actual Snyk token and org ID
- Restart Claude Code

## Verification

1. **Test Snyk CLI authentication:**
   ```bash
   SNYK_TOKEN="your-token" SNYK_ORG="your-org-id" snyk whoami
   ```
   Should show your username and organization.

2. **Test the server starts:**
   ```bash
   SNYK_TOKEN="your-token" SNYK_ORG_ID="your-org-id" node build/index.js
   ```
   Should start without authentication errors.

## Quick Test

Once configured, try these tools:
- `snyk_auth_status` - Check authentication
- `snyk_sca_scan --severity "high"` - Scan dependencies

## Troubleshooting

**Authentication fails:**
- Check token/org ID are correct in `.mcp.json`
- Restart Claude Code after config changes
- Verify Snyk CLI works: `snyk --version`

**Server won't start:**
- Install Snyk CLI globally: `npm install -g snyk`
- Check file permissions on the server directory
- Ensure absolute paths in configuration

**Organization ID format:**
- Use format like `john.doe` or `my-company`
- Find exact format in your Snyk organization settings