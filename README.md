# Snyk MCP Server

Model Context Protocol server for Snyk security scanning with Amazon Q Developer. Provides vulnerability scanning, automated fixes, and security analysis.

## Features

### 🔍 Comprehensive Scanning
- **SCA (Software Composition Analysis)**: Scan dependencies for known vulnerabilities
- **Code Analysis**: Static security analysis for source code vulnerabilities
- **Infrastructure as Code**: Security configuration analysis for Terraform, CloudFormation, Kubernetes
- **Container Security**: Scan Docker images and container configurations

### 🛠️ Automated Remediation
- **Smart Fixes**: Intelligent vulnerability fixing with dependency upgrades
- **Patch Management**: Apply security patches automatically
- **Dry-Run Mode**: Preview changes before applying fixes
- **Configuration Corrections**: Fix IaC security misconfigurations

### 📊 Progress & Tracking
- **Rescan Comparison**: Compare scan results over time
- **Vulnerability Tracking**: Monitor resolved, new, and remaining issues
- **Severity Filtering**: Focus on critical and high-severity vulnerabilities
- **Historical Analysis**: Track security improvements over time

### 🔐 Security & Reliability
- **Environment Authentication**: Secure token-based authentication
- **Rate Limiting**: Prevent API abuse with configurable limits
- **Input Validation**: Comprehensive parameter and path validation
- **Data Protection**: Automatic redaction of sensitive information
- **Sandboxed Execution**: Safe command execution with timeouts

## Available Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `snyk_auth_status` | Check authentication | None |
| `snyk_sca_scan` | Dependency vulnerabilities | `path`, `severity` |
| `snyk_code_scan` | Code security issues | `path`, `severity` |
| `snyk_iac_scan` | Infrastructure misconfigurations | `path`, `severity` |
| `snyk_container_scan` | Container vulnerabilities | `image` (required), `severity` |
| `snyk_fix` | Apply automated fixes | `path`, `dryRun` |
| `snyk_rescan` | Compare scan results | `path`, `compareWith` |

**Common Parameters:**
- `severity`: `low`, `medium`, `high`, `critical`
- `path`: Directory to scan (defaults to current)
- `dryRun`: Preview fixes without applying

## Usage Examples

**Basic Scanning:**
```bash
snyk_sca_scan --severity "high"
snyk_code_scan --path "./src"
snyk_container_scan --image "node:18-alpine"
```

**Fix Workflow:**
```bash
snyk_fix --dryRun true  # Preview first
snyk_fix                # Apply fixes
snyk_rescan             # Verify
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