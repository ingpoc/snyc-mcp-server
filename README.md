# Snyk MCP Server

Production-ready Model Context Protocol server for comprehensive security scanning with Snyk. Optimized for AI assistants with intelligent project analysis, automated vulnerability detection, and guided remediation workflows.

## Features

### 🧠 AI-Optimized Workflows
- **Smart Project Analysis**: Automatically detects project type and recommends relevant scans
- **Intelligent Entry Point**: `snyk_scan_recommendations` guides AI assistants to optimal security assessment
- **Context-Efficient Responses**: Concise summaries save AI context while providing complete vulnerability data
- **Clear Parameter Guidance**: Explicit format examples prevent common usage errors

### 🔍 Comprehensive Security Scanning
- **SCA (Software Composition Analysis)**: Dependency vulnerability detection with auto-fix recommendations
- **Static Code Analysis**: Source code security vulnerabilities with manual fix guidance  
- **Infrastructure as Code**: Security misconfigurations in Terraform, Docker, Kubernetes, CloudFormation
- **Container Security**: Docker image vulnerability scanning with layer-specific results

### 🛠️ Automated & Guided Remediation
- **Smart Fix Classification**: Distinguishes between auto-fixable (snyk_fix) vs manual code changes
- **Safe Fix Workflow**: Mandatory preview mode before applying destructive changes
- **Fix Method Guidance**: Specific instructions for dependency upgrades, patches, or code modifications
- **Verification Loop**: Re-scan capabilities to confirm vulnerability resolution

### 📊 Data Integrity & Reliability  
- **Vulnerability Count Verification**: Ensures no data loss between raw scans and AI responses
- **Structured Response Format**: Consistent object format across all scan types
- **Severity-Based Filtering**: Configurable thresholds for production vs development scanning
- **Project Type Detection**: Pre-scan validation prevents unnecessary scan failures

### 🔐 Production-Ready Security
- **OAuth Authentication Flow**: Secure browser-based authentication with session token management
- **Input Validation**: Comprehensive path, image, and parameter validation with helpful error messages
- **Rate Limiting & Timeouts**: Prevents API abuse and handles long-running scans
- **Sensitive Data Protection**: Automatic redaction of tokens and credentials in logs

## Available Tools

### Core Tools

| Tool | Purpose | Parameters | AI Usage |
|------|---------|------------|----------|
| **`snyk_scan_recommendations`** | **START HERE** - Analyze project and recommend scans | `path` (optional) | Use first for unknown projects |
| `snyk_auth_status` | Verify authentication status | None | Run before first scan or if auth errors |
| `snyk_sca_scan` | Dependency vulnerabilities | `path`, `severity`, `json` | For package.json, requirements.txt, etc. |
| `snyk_code_scan` | Static code security analysis | `path`, `severity`, `sarif` | For source code vulnerabilities |
| `snyk_iac_scan` | Infrastructure security configs | `path`, `severity`, `json` | For Terraform, Docker, K8s files |
| `snyk_container_scan` | Container image vulnerabilities | `image` (**required**), `severity` | For Docker images before deployment |
| `snyk_fix` | Apply automated dependency fixes | `path`, `dryRun` | Auto-fix upgradable vulnerabilities |
| `snyk_rescan` | Compare results over time | `path`, `compareWith` | Track remediation progress |

### Parameter Guidelines

**Path Parameters:**
- **Format**: Use absolute paths (`/full/path/to/project`) for best reliability
- **Relative paths** like `folder/subfolder` may fail
- **Omit parameter** to scan current directory

**Severity Levels:**
- `critical`: Urgent fixes only (production blocking)
- `high`: Production deployments (recommended minimum)  
- `medium`: Comprehensive development scanning
- `low`: All issues including informational

**Container Images:**
- **Format**: `name:tag` or `registry/name:tag`
- **Examples**: `node:18-alpine`, `nginx:latest`, `myregistry.com/app:v1.0`

## AI Assistant Workflow Examples

### Optimal Workflow for New Projects
```javascript
// 1. Analyze project structure
snyk_scan_recommendations()

// 2. Check authentication 
snyk_auth_status()

// 3. Run recommended scans
snyk_sca_scan({ severity: "medium" })
snyk_code_scan({ severity: "medium" })
```

### Production Security Assessment
```javascript
// Focus on critical vulnerabilities
snyk_sca_scan({ 
  path: "/project/path", 
  severity: "high" 
})

snyk_container_scan({ 
  image: "myapp:latest", 
  severity: "critical" 
})
```

### Safe Fix Application Workflow
```javascript
// 1. Preview fixes first
snyk_fix({ 
  path: "/project/path", 
  dryRun: true 
})

// 2. Apply if preview acceptable
snyk_fix({ 
  path: "/project/path", 
  dryRun: false 
})

// 3. Verify resolution
snyk_sca_scan({ 
  path: "/project/path" 
})
```

### Response Format
All tools return optimized responses:
```javascript
{
  "summary": {
    "totalIssues": 5,
    "critical": 1, "high": 2, "medium": 2, "low": 0,
    "fixableBySnyk": 3, "requiresManualFix": 2
  },
  "vulnerabilities": [/* detailed vulnerability objects */],
  "nextSteps": [/* prioritized action items */]
}
```

## Setup

See [HOWTO.md](HOWTO.md) for complete setup instructions.

## Architecture

- **Authentication**: Environment-based with Snyk API tokens
- **Transport**: stdio for MCP communication
- **Security**: Input validation, rate limiting, sandboxed execution
- **Error Handling**: Comprehensive with sensitive data redaction

## Requirements

- Node.js 18+
- Snyk CLI
- Snyk account with API token