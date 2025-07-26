# Snyk MCP Server Setup Guide

Complete setup guide for the production-ready Snyk MCP server with AI-optimized security scanning.

## Prerequisites

- **Snyk Account**: Free account at [snyk.io](https://snyk.io) with API token access
- **Snyk CLI**: `npm install -g snyk` (latest version)
- **Node.js**: Version 18+ required
- **Claude Code**: MCP-compatible client for AI integration

## Installation

1. **Clone and build the server:**
   ```bash
   git clone <repository-url>
   cd snyk-mcp-server
   npm install
   npx tsc  # Build TypeScript
   ```

2. **Install Snyk CLI globally:**
   ```bash
   npm install -g snyk
   snyk --version  # Verify installation
   ```

3. **Get Snyk credentials:**
   - **API Token**: Visit [app.snyk.io/account](https://app.snyk.io/account) → "API Token"
   - **Organization ID**: Optional, found in Snyk org settings (format: `john.doe`)

## Configuration

### MCP Server Configuration

Add to your `~/.claude/.mcp.json`:

```json
{
  "mcpServers": {
    "snyk": {
      "command": "node",
      "args": ["/absolute/path/to/snyk-mcp-server/build/index.js"],
      "env": {
        "SNYK_TOKEN": "your-snyk-api-token-here"
      }
    }
  }
}
```

### Configuration Notes

- **Path**: Use absolute path to `build/index.js`
- **SNYK_TOKEN**: Your API token from Snyk account settings
- **SNYK_ORG_ID**: Optional - only needed for enterprise accounts with multiple orgs
- **Restart**: Restart Claude Code after configuration changes

### Authentication Flow

The server uses OAuth authentication:
1. **API Token**: Used to initiate authentication flow
2. **Browser OAuth**: Opens browser for user approval (first time)
3. **Session Tokens**: Created automatically for subsequent scans

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