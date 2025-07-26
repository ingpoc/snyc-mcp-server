#!/usr/bin/env node

/**
 * SNYK MCP SERVER - AI ASSISTANT USAGE GUIDE
 * 
 * OPTIMAL WORKFLOW FOR AI ASSISTANTS:
 * 1. NEW PROJECTS: Start with snyk_scan_recommendations to analyze project structure
 * 2. AUTHENTICATION: Run snyk_auth_status before first scan or if auth errors occur
 * 3. RUN RECOMMENDED SCANS based on project analysis:
 *    - snyk_sca_scan: For dependency vulnerabilities (if dependencies found)
 *    - snyk_code_scan: For source code security issues (if code files found)
 *    - snyk_iac_scan: For infrastructure security (if IaC files found)
 *    - snyk_container_scan: For Docker images (requires specific image name)
 * 4. FOR FIXES: Always use dryRun=true first, then apply if acceptable
 * 
 * AUTHENTICATION TROUBLESHOOTING:
 * - If snyk_auth_status shows authenticated=false, user needs OAuth setup
 * - OAuth flow: MCP server opens browser, user approves, creates session tokens
 * - Requires SNYK_TOKEN environment variable with valid API token
 * - User must have Snyk CLI installed and accessible
 * 
 * COMMON SCANNING PATTERNS:
 * - New project assessment: scan_recommendations → auth_status → recommended scans
 * - Known project security: auth_status → sca_scan → code_scan
 * - Pre-deployment security: auth_status → sca_scan (severity=high) → container_scan
 * - Post-fix verification: auth_status → rescan with compareWith previous results
 * - Infrastructure review: scan_recommendations → auth_status → iac_scan (if IaC detected)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

import { SnykAuth } from './auth/snyk-auth.js';
import { SnykScaTool } from './tools/sca-scan.js';
import { SnykCodeTool } from './tools/code-scan.js';
import { SnykIacTool } from './tools/iac-scan.js';
import { SnykContainerTool } from './tools/container-scan.js';
import { SnykFixTool } from './tools/fix.js';
import { SnykRescanTool } from './tools/rescan.js';
import { ProjectDetector } from './utils/project-detector.js';
import { AIOptimizedResponseFormatter } from './utils/ai-optimized-responses.js';
import { RateLimiter, validateApiToken, validateOrgId, validateContainerImage, redactSensitiveInfo } from './utils/security.js';

// Zod schemas for validation
const ScanArgsSchema = z.object({
  path: z.string().optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  json: z.boolean().default(true).optional(),
});

const CodeScanArgsSchema = z.object({
  path: z.string().optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  sarif: z.boolean().default(true).optional(),
});

const ContainerScanArgsSchema = z.object({
  image: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  json: z.boolean().default(true).optional(),
});

const FixArgsSchema = z.object({
  path: z.string().optional(),
  dryRun: z.boolean().default(false).optional(),
});

const RescanArgsSchema = z.object({
  path: z.string().optional(),
  compareWith: z.string().optional(),
});

const ScanRecommendationsArgsSchema = z.object({
  path: z.string().optional(),
});

class SnykMcpServer {
  private server: Server;
  private auth: SnykAuth;
  private rateLimiter: RateLimiter;
  private projectDetector: ProjectDetector;
  private scaTool?: SnykScaTool;
  private codeTool?: SnykCodeTool;
  private iacTool?: SnykIacTool;
  private containerTool?: SnykContainerTool;
  private fixTool?: SnykFixTool;
  private rescanTool?: SnykRescanTool;

  constructor() {
    this.server = new Server(
      {
        name: 'snyk-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.auth = new SnykAuth();
    this.rateLimiter = new RateLimiter(50, 60000);
    this.projectDetector = new ProjectDetector();
    
    setInterval(() => this.rateLimiter.cleanup(), 5 * 60 * 1000);

    this.setupHandlers();
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'snyk_auth_status',
            description: 'CHECK AUTHENTICATION: Verify Snyk authentication status before running scans. Use this tool: 1) Before first scan in a session, 2) When scans fail with authentication errors, 3) To troubleshoot auth issues. This verifies session tokens from OAuth browser flow. If authenticated=false, user needs to complete OAuth flow (MCP opens browser automatically). Returns authentication state, username, and organization.',
            inputSchema: {
              type: 'object',
              properties: {},
              additionalProperties: false,
            },
            annotations: {
              title: 'Authentication Status Check',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: false,
            },
          },
          {
            name: 'snyk_sca_scan',
            description: 'SOFTWARE COMPOSITION ANALYSIS: Scan project dependencies for known vulnerabilities (CVEs). Use this for checking third-party packages in package.json, requirements.txt, Gemfile, etc. WORKFLOW: 1) Ensure authentication (run snyk_auth_status if first scan), 2) Navigate to project directory or provide path parameter, 3) Run this scan. Results include vulnerability details, CVSS scores, and upgrade paths. Use severity parameter to filter results (e.g., "high" for production deployments).',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'IMPORTANT: Use absolute path for best results (e.g., "/full/path/to/project"). Relative paths like "folder/subfolder" may fail. If scanning current directory, omit this parameter entirely. Target directory must contain dependency files like package.json, requirements.txt, etc.',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'USAGE: "critical" (urgent fixes only), "high" (production deployments), "medium" (comprehensive scan), "low" (all issues). Default: no filter (shows all).',
                },
                json: {
                  type: 'boolean',
                  description: 'Return structured JSON results (recommended). Set to true for programmatic analysis.',
                  default: true,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Dependency Vulnerability Scan (SCA)',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_code_scan',
            description: 'STATIC CODE ANALYSIS: Scan source code for security vulnerabilities, injection flaws, and coding best practices violations. Analyzes JavaScript, TypeScript, Python, Java, and other languages. WORKFLOW: 1) Ensure authentication (run snyk_auth_status if first scan), 2) Point to directory with source code, 3) Run scan. Results include precise file locations, line numbers, severity levels, and fix examples. Use this to find issues like SQL injection, XSS, command injection, etc.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'IMPORTANT: Use absolute path for best results (e.g., "/full/path/to/code"). Relative paths may fail. Omit to scan current directory. Target must contain source code files (.js, .ts, .py, .java, etc.).',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Filter by minimum severity. Use "high" for critical security issues, "medium" for comprehensive review.',
                },
                sarif: {
                  type: 'boolean',
                  description: 'Return SARIF format with precise file locations and fix examples (recommended).',
                  default: true,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Source Code Security Scan',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_iac_scan',
            description: 'INFRASTRUCTURE SECURITY: Scan Infrastructure-as-Code files for security misconfigurations and compliance violations. Supports Terraform (.tf), CloudFormation (.yml/.yaml), Kubernetes manifests, Dockerfiles, and Helm charts. USAGE: Only run if your project contains IaC files. Common issues found: exposed secrets, overly permissive policies, unencrypted storage, public access violations.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to directory containing IaC files (.tf, .yaml, Dockerfile, docker-compose.yml, etc.). Will fail if no IaC files found.',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Filter misconfigurations by severity. Use "critical" for production infrastructure, "medium" for development.',
                },
                json: {
                  type: 'boolean',
                  description: 'Return structured JSON with remediation guidance and policy recommendations.',
                  default: true,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Infrastructure Security Scan (IaC)',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_container_scan',
            description: 'CONTAINER SECURITY: Scan Docker images for vulnerabilities in base images and installed packages. Use this for Docker images before deployment. EXAMPLES: "node:18", "nginx:latest", "myregistry.com/app:v1.0". Scans both OS packages and application dependencies within the container. Critical for production deployments to ensure secure base images.',
            inputSchema: {
              type: 'object',
              properties: {
                image: {
                  type: 'string',
                  description: 'REQUIRED: Docker image name and tag. FORMAT: "name:tag" or "registry/name:tag". EXAMPLES: "node:18-alpine", "nginx:latest", "myregistry.com/myapp:v1.0". Must be pullable from Docker registry.',
                  pattern: '^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?([:/][a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Filter vulnerabilities by severity. For production containers: use "high" or "critical". For development: "medium".',
                },
                json: {
                  type: 'boolean',
                  description: 'Return structured JSON with vulnerability details and remediation advice.',
                  default: true,
                },
              },
              required: ['image'],
              additionalProperties: false,
            },
            annotations: {
              title: 'Container Image Security Scan',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_fix',
            description: 'AUTOMATED REMEDIATION: Apply fixes for dependency vulnerabilities found in scans. Updates package versions and applies patches automatically. AI WORKFLOW: 1) Run with dryRun=true to preview fixes, 2) If fixes look safe and correct, run with dryRun=false to apply them, 3) Re-scan to verify fixes. SAFETY: Always preview first - this modifies package files and lockfiles.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'IMPORTANT: Use absolute path for reliability (e.g., "/full/path/to/project"). Must contain dependency files. Omit to fix current directory.',
                },
                dryRun: {
                  type: 'boolean',
                  description: 'SAFETY FIRST: Set to true to preview fixes without applying them. Only set to false after reviewing dry run results.',
                  default: false,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Automated Vulnerability Remediation (DESTRUCTIVE)',
              readOnlyHint: false,
              destructiveHint: true,
              idempotentHint: false,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_rescan',
            description: 'COMPREHENSIVE SECURITY AUDIT: Run all security scans (SCA, Code, IaC) and compare with previous results to track remediation progress. Use this for complete security assessment or after applying fixes. WORKFLOW: 1) Run individual scans first to understand issues, 2) Apply fixes, 3) Use rescan to verify improvements and track progress.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to project directory for comprehensive security scanning. Should contain code, dependencies, and/or IaC files.',
                },
                compareWith: {
                  type: 'string',
                  description: 'Path to previous scan results file (.json) for progress tracking. Shows new, resolved, and remaining vulnerabilities.',
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Comprehensive Security Rescan & Progress Tracking',
              readOnlyHint: false,
              destructiveHint: false,
              idempotentHint: false,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_scan_recommendations',
            description: 'START HERE FOR NEW PROJECTS: Analyze project structure and recommend which Snyk scans are applicable. This is the optimal entry point for AI assistants working with unknown projects. It detects dependencies, code files, and IaC files, then provides a tailored security scanning strategy. Prevents unnecessary scan failures and guides you to the most relevant tools for comprehensive security assessment.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to project directory to analyze. Defaults to current directory.',
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Smart Project Analysis & Scan Recommendations (START HERE)',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: false,
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      if (!this.rateLimiter.isAllowed('default')) {
        throw new McpError(ErrorCode.InternalError, 'Rate limit exceeded. Please wait before making more requests.');
      }

      try {
        switch (name) {
          case 'snyk_auth_status': {
            const status = await this.auth.getAuthStatus();
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(status, null, 2),
              }],
              structuredContent: status,
            };
          }

          case 'snyk_sca_scan': {
            this.ensureAuthenticated();
            const scanArgs = ScanArgsSchema.parse(args);
            const results = await this.scaTool!.scan(scanArgs);
            const optimized = AIOptimizedResponseFormatter.formatScaScanResults(results);
            
            // Data integrity check
            if (results.vulnerabilities.length !== optimized.vulnerabilities.length) {
              console.warn(`SCA Data integrity warning: Raw vulnerabilities ${results.vulnerabilities.length} vs Formatted ${optimized.vulnerabilities.length}`);
            }
            
            return {
              content: [{
                type: 'text',
                text: `Dependencies Scan: ${optimized.summary.totalIssues} vulnerabilities found (${optimized.summary.critical} critical, ${optimized.summary.high} high, ${optimized.summary.medium} medium, ${optimized.summary.low} low). ${optimized.summary.fixableBySnyk} auto-fixable via snyk_fix.`,
              }],
              structuredContent: {
                ...optimized,
                _dataIntegrity: {
                  rawVulnerabilitiesCount: results.vulnerabilities.length,
                  formattedVulnsCount: optimized.vulnerabilities.length,
                  verified: results.vulnerabilities.length === optimized.vulnerabilities.length
                }
              },
            };
          }

          case 'snyk_code_scan': {
            this.ensureAuthenticated();
            const scanArgs = CodeScanArgsSchema.parse(args);
            const results = await this.codeTool!.scan(scanArgs);
            const optimized = AIOptimizedResponseFormatter.formatCodeScanResults(results);
            
            // Data integrity check
            if (results.length !== optimized.vulnerabilities.length) {
              console.warn(`Data integrity warning: Raw results ${results.length} vs Formatted ${optimized.vulnerabilities.length}`);
            }
            
            return {
              content: [{
                type: 'text',
                text: `Code Security Scan: ${optimized.summary.totalIssues} vulnerabilities found (${optimized.summary.critical} critical, ${optimized.summary.high} high, ${optimized.summary.medium} medium, ${optimized.summary.low} low). All require manual code fixes.`,
              }],
              structuredContent: {
                ...optimized,
                _dataIntegrity: {
                  rawIssuesCount: results.length,
                  formattedVulnsCount: optimized.vulnerabilities.length,
                  verified: results.length === optimized.vulnerabilities.length
                }
              },
            };
          }

          case 'snyk_iac_scan': {
            this.ensureAuthenticated();
            const scanArgs = ScanArgsSchema.parse(args);
            const results = await this.iacTool!.scan(scanArgs);
            const optimized = AIOptimizedResponseFormatter.formatIacScanResults(results);
            
            return {
              content: [{
                type: 'text',
                text: `Infrastructure Scan: ${optimized.summary.totalIssues} misconfigurations found (${optimized.summary.critical} critical, ${optimized.summary.high} high, ${optimized.summary.medium} medium, ${optimized.summary.low} low). Configuration changes required.`,
              }],
              structuredContent: optimized,
            };
          }

          case 'snyk_container_scan': {
            this.ensureAuthenticated();
            const scanArgs = ContainerScanArgsSchema.parse(args);
            
            if (!validateContainerImage(scanArgs.image)) {
              throw new Error('Invalid container image format. Image must be a valid Docker image reference.');
            }

            const results = await this.containerTool!.scan(scanArgs);
            const optimized = AIOptimizedResponseFormatter.formatContainerScanResults(results);
            
            return {
              content: [{
                type: 'text',
                text: `Container Scan: ${optimized.summary.totalIssues} vulnerabilities found (${optimized.summary.critical} critical, ${optimized.summary.high} high, ${optimized.summary.medium} medium, ${optimized.summary.low} low). Container image security review required.`,
              }],
              structuredContent: {
                ...optimized,
                _dataIntegrity: {
                  rawIssuesCount: results.length,
                  formattedVulnsCount: optimized.vulnerabilities.length,
                  verified: results.length === optimized.vulnerabilities.length
                }
              },
            };
          }

          case 'snyk_fix': {
            this.ensureAuthenticated();
            const fixArgs = FixArgsSchema.parse(args);
            const results = await this.fixTool!.fix(fixArgs);
            
            const summary = fixArgs.dryRun 
              ? `Fix Preview: ${results.fixes.length} dependencies can be fixed, ${results.errors.length} errors`
              : `Fixes Applied: ${results.fixes.length} dependencies updated, ${results.errors.length} errors`;
            
            return {
              content: [{
                type: 'text',
                text: summary,
              }],
              structuredContent: {
                ...results,
                isDryRun: fixArgs.dryRun,
                nextStep: fixArgs.dryRun 
                  ? 'Run snyk_fix with dryRun=false to apply these fixes'
                  : 'Run snyk_sca_scan to verify vulnerabilities are resolved'
              },
            };
          }

          case 'snyk_rescan': {
            this.ensureAuthenticated();
            const rescanArgs = RescanArgsSchema.parse(args);
            const results = await this.rescanTool!.rescan(rescanArgs);
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(results, null, 2),
              }],
              structuredContent: results,
            };
          }

          case 'snyk_scan_recommendations': {
            const scanRecommendationsArgs = ScanRecommendationsArgsSchema.parse(args);
            const detection = await this.projectDetector.detectProject(scanRecommendationsArgs.path);
            const recommendations = this.projectDetector.getRecommendations(detection);
            
            const report = {
              projectAnalysis: {
                path: scanRecommendationsArgs.path || '.',
                hasDependencies: detection.hasDependencies,
                hasCode: detection.hasCode,
                hasIaC: detection.hasIaC,
                dependencyFiles: detection.dependencyFiles,
                iacFiles: detection.iacFiles.slice(0, 10), // Limit to avoid overflow
                packageManager: detection.packageManager,
              },
              recommendedScans: recommendations,
              nextSteps: recommendations.length > 0 
                ? 'NEXT: 1) Run snyk_auth_status to verify authentication, 2) Execute recommended scans in order, 3) Address any vulnerabilities found.'
                : 'No scannable files detected. Ensure you are in the correct project directory or try a different path.'
            };
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(report, null, 2),
              }],
              structuredContent: report,
            };
          }

          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (error) {
        const message = error instanceof Error ? redactSensitiveInfo(error.message) : 'Unknown error';
        
        if (error instanceof McpError) {
          throw error;
        }
        
        console.error(`Tool execution failed for ${name}:`, redactSensitiveInfo(message));
        throw new McpError(ErrorCode.InternalError, `Tool execution failed: ${message}`);
      }
    });
  }

  private async initialize(options: { token?: string; orgId?: string; baseUrl?: string } = {}): Promise<void> {
    const apiToken = options.token || process.env.SNYK_TOKEN || process.env.SNYK_API_TOKEN;
    const orgId = options.orgId || process.env.SNYK_ORG_ID || process.env.SNYK_ORG;
    const baseUrl = options.baseUrl || process.env.SNYK_API || process.env.SNYK_API_URL;

    if (!apiToken) {
      throw new Error('API token is required. Provide it via --token argument, SNYK_TOKEN, or SNYK_API_TOKEN environment variable.');
    }

    if (!validateApiToken(apiToken)) {
      throw new Error('Invalid API token format. Token must be at least 20 characters and contain only alphanumeric characters, hyphens, and underscores.');
    }
    
    if (orgId && !validateOrgId(orgId)) {
      throw new Error('Invalid organization ID format. Organization ID must be at least 3 characters and contain only alphanumeric characters, hyphens, underscores, and dots.');
    }

    await this.auth.validateSnykCli();
    await this.auth.authenticate(apiToken, orgId, baseUrl);
    this.initializeTools();
  }

  private ensureAuthenticated(): void {
    if (!this.auth.isAuthenticated()) {
      throw new Error('Snyk authentication required. TROUBLESHOOTING: 1) Check snyk_auth_status to see current state, 2) If not authenticated, user needs to complete OAuth flow in browser (MCP server will open browser automatically), 3) Ensure SNYK_TOKEN environment variable is set with valid API token, 4) Verify Snyk CLI is installed ("snyk --version"), 5) Check organization access permissions.');
    }
  }

  private initializeTools(): void {
    const config = this.auth.getConfig();
    if (!config) {
      throw new Error('No authentication config available');
    }

    this.scaTool = new SnykScaTool(config);
    this.codeTool = new SnykCodeTool(config);
    this.iacTool = new SnykIacTool(config);
    this.containerTool = new SnykContainerTool(config);
    this.fixTool = new SnykFixTool(config);
    this.rescanTool = new SnykRescanTool(config);
  }

  async run(options: { token?: string; orgId?: string; baseUrl?: string } = {}): Promise<void> {
    await this.initialize(options);
    
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}

function parseCommandLineArgs(): { token?: string; orgId?: string; baseUrl?: string } {
  const args = process.argv.slice(2);
  const options: { token?: string; orgId?: string; baseUrl?: string } = {};
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];
    
    switch (arg) {
      case '--token':
      case '-t':
        if (nextArg && !nextArg.startsWith('-')) {
          options.token = nextArg;
          i++;
        }
        break;
      case '--org-id':
      case '--org':
      case '-o':
        if (nextArg && !nextArg.startsWith('-')) {
          options.orgId = nextArg;
          i++;
        }
        break;
      case '--base-url':
      case '--api-url':
      case '-u':
        if (nextArg && !nextArg.startsWith('-')) {
          options.baseUrl = nextArg;
          i++;
        }
        break;
      case '--help':
      case '-h':
        console.log(`
Snyk MCP Server

Usage: node build/index.js [options]

Options:
  -t, --token <token>       Snyk API token (can also use SNYK_TOKEN env var)
  -o, --org-id <org>        Snyk organization ID (can also use SNYK_ORG_ID env var)
  -u, --base-url <url>      Snyk API base URL (can also use SNYK_API env var)
  -h, --help                Show this help message

Environment Variables:
  SNYK_TOKEN               Snyk API token
  SNYK_API_TOKEN           Alternative to SNYK_TOKEN
  SNYK_ORG_ID              Snyk organization ID
  SNYK_ORG                 Alternative to SNYK_ORG_ID
  SNYK_API                 Snyk API base URL
  SNYK_API_URL             Alternative to SNYK_API

Note: Command line arguments take precedence over environment variables.
        `);
        process.exit(0);
    }
  }
  
  return options;
}

async function main(): Promise<void> {
  const options = parseCommandLineArgs();
  const server = new SnykMcpServer();
  await server.run(options);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Server failed to start:', error);
    process.exit(1);
  });
}