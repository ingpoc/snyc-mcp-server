#!/usr/bin/env node

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

class SnykMcpServer {
  private server: Server;
  private auth: SnykAuth;
  private rateLimiter: RateLimiter;
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
    
    setInterval(() => this.rateLimiter.cleanup(), 5 * 60 * 1000);

    this.setupHandlers();
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'snyk_auth_status',
            description: 'Check the current Snyk authentication status and verify credentials.',
            inputSchema: {
              type: 'object',
              properties: {},
              additionalProperties: false,
            },
            annotations: {
              title: 'Authentication Status',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: false,
            },
          },
          {
            name: 'snyk_sca_scan',
            description: 'Scan for open-source dependency vulnerabilities using Snyk. Analyzes package.json, requirements.txt, and other dependency files.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to scan (defaults to current directory). Must be a valid directory path.',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Minimum severity level to report. Only vulnerabilities of this severity or higher will be included.',
                },
                json: {
                  type: 'boolean',
                  description: 'Return results in JSON format for structured parsing.',
                  default: true,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'SCA Vulnerability Scan',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_code_scan',
            description: 'Scan source code for security vulnerabilities, code quality issues, and potential bugs using Snyk Code static analysis.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to scan (defaults to current directory). Must contain source code files.',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Minimum severity level to report. Filters results by severity threshold.',
                },
                sarif: {
                  type: 'boolean',
                  description: 'Return results in SARIF format with detailed location information.',
                  default: true,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Code Security Scan',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_iac_scan',
            description: 'Scan Infrastructure-as-Code configurations (Terraform, CloudFormation, Kubernetes, Docker) for security misconfigurations and compliance issues.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to scan (defaults to current directory). Should contain IaC files like .tf, .yaml, Dockerfile, etc.',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Minimum severity level to report. Filters misconfigurations by severity.',
                },
                json: {
                  type: 'boolean',
                  description: 'Return results in JSON format with detailed remediation guidance.',
                  default: true,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Infrastructure as Code Scan',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_container_scan',
            description: 'Scan container images for vulnerabilities in base images and installed packages. Supports Docker images from registries.',
            inputSchema: {
              type: 'object',
              properties: {
                image: {
                  type: 'string',
                  description: 'Container image to scan (e.g., node:18-alpine, nginx:latest, myregistry.com/myapp:v1.0). Must be a valid image reference.',
                  pattern: '^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?([:/][a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$',
                },
                severity: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Minimum severity level to report. Filters container vulnerabilities by severity.',
                },
                json: {
                  type: 'boolean',
                  description: 'Return results in JSON format with detailed vulnerability information.',
                  default: true,
                },
              },
              required: ['image'],
              additionalProperties: false,
            },
            annotations: {
              title: 'Container Image Scan',
              readOnlyHint: true,
              destructiveHint: false,
              idempotentHint: true,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_fix',
            description: 'Apply automated fixes for vulnerabilities including dependency upgrades, patches, and configuration corrections. Use with caution in production.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to apply fixes (defaults to current directory). Must be a valid project directory.',
                },
                dryRun: {
                  type: 'boolean',
                  description: 'Preview mode - show what would be fixed without applying changes. Recommended for safety.',
                  default: false,
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Automated Vulnerability Fix',
              readOnlyHint: false,
              destructiveHint: true,
              idempotentHint: false,
              openWorldHint: true,
            },
          },
          {
            name: 'snyk_rescan',
            description: 'Perform comprehensive rescan across all vulnerability types (SCA, Code, IaC) and compare with previous results to track remediation progress.',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to rescan (defaults to current directory). Should contain the project to analyze.',
                },
                compareWith: {
                  type: 'string',
                  description: 'Path to previous scan results file for comparison. Shows resolved, new, and remaining issues.',
                },
              },
              additionalProperties: false,
            },
            annotations: {
              title: 'Comprehensive Rescan & Compare',
              readOnlyHint: false,
              destructiveHint: false,
              idempotentHint: false,
              openWorldHint: true,
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
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(results, null, 2),
              }],
              structuredContent: results,
            };
          }

          case 'snyk_code_scan': {
            this.ensureAuthenticated();
            const scanArgs = CodeScanArgsSchema.parse(args);
            const results = await this.codeTool!.scan(scanArgs);
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(results, null, 2),
              }],
              structuredContent: { 
                results: results,
                summary: Array.isArray(results) ? `Found ${results.length} code issues` : 'Code scan completed'
              },
            };
          }

          case 'snyk_iac_scan': {
            this.ensureAuthenticated();
            const scanArgs = ScanArgsSchema.parse(args);
            const results = await this.iacTool!.scan(scanArgs);
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(results, null, 2),
              }],
              structuredContent: results,
            };
          }

          case 'snyk_container_scan': {
            this.ensureAuthenticated();
            const scanArgs = ContainerScanArgsSchema.parse(args);
            
            if (!validateContainerImage(scanArgs.image)) {
              throw new Error('Invalid container image format. Image must be a valid Docker image reference.');
            }

            const results = await this.containerTool!.scan(scanArgs);
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(results, null, 2),
              }],
              structuredContent: results,
            };
          }

          case 'snyk_fix': {
            this.ensureAuthenticated();
            const fixArgs = FixArgsSchema.parse(args);
            const results = await this.fixTool!.fix(fixArgs);
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify(results, null, 2),
              }],
              structuredContent: results,
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
      throw new Error('Authentication failed during server initialization. Please check your environment variables.');
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