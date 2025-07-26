import { executeCommand, buildSnykCommand } from '../utils/exec.js';
import { ProjectDetector } from '../utils/project-detector.js';
import type { SnykIacIssue, SnykConfig } from '../types/snyk.js';
import type { SnykIacScanArgs } from '../types/mcp.js';

interface SnykIacScanResult {
  infrastructureAsCodeIssues: Array<{
    id: string;
    title: string;
    severity: string;
    msg: string;
    resolve: string;
    impact: string;
    references?: string[];
    path: string[];
    cloudConfigPath: string[];
    documentation?: string;
    isIgnored: boolean;
    resource?: string;
  }>;
}

export class SnykIacTool {
  private detector = new ProjectDetector();
  
  constructor(private config: SnykConfig) {}

  async scan(args: SnykIacScanArgs): Promise<SnykIacIssue[]> {
    const scanPath = args.path || '.';
    
    // Check if project has IaC files before scanning
    const detection = await this.detector.detectProject(scanPath);
    if (!detection.hasIaC) {
      throw new Error(`No Infrastructure as Code files found in '${scanPath}'. IaC scan requires files like Dockerfile, *.tf, *.yml, docker-compose.yml, etc. Consider using snyk_code_scan for source code or snyk_sca_scan for dependencies.`);
    }
    const command = buildSnykCommand('iac test', [
      args.path || '.',
      ...(args.severity ? [`--severity-threshold=${args.severity}`] : []),
    ], {
      org: this.config.orgId,
      json: args.json,
    });

    const result = await executeCommand(command, {
      cwd: args.path || process.cwd(),
      env: {
        SNYK_TOKEN: this.config.apiToken,
        ...(this.config.orgId && { SNYK_ORG: this.config.orgId }),
        ...(this.config.baseUrl && { SNYK_API: this.config.baseUrl }),
      },
    });

    if (result.exitCode !== 0 && result.exitCode !== 1) {
      // Provide specific error messages for common failures
      const errorOutput = result.stderr || result.stdout;
      if (errorOutput.includes('No IaC files found') || errorOutput.includes('No supported files found')) {
        throw new Error(`No supported IaC files found in '${scanPath}'. IaC scan requires Terraform (.tf), Kubernetes (.yml/.yaml), Dockerfile, or docker-compose files.`);
      } else if (errorOutput.includes('Not authorised')) {
        throw new Error('Authentication failed. Please run snyk_auth_status to check authentication or contact your Snyk administrator for access.');
      } else if (errorOutput.includes('Missing option')) {
        throw new Error(`Snyk command error: ${errorOutput}. Check scan parameters and try again.`);
      } else {
        throw new Error(`Snyk IaC scan failed: ${errorOutput}`);
      }
    }

    if (result.stdout.includes('No issues found') || result.stdout.trim() === '') {
      return [];
    }

    try {
      const scanResult = JSON.parse(result.stdout) as SnykIacScanResult;
      return this.parseIacResults(scanResult);
    } catch (error) {
      throw new Error(`Failed to parse Snyk IaC scan results: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private parseIacResults(result: SnykIacScanResult): SnykIacIssue[] {
    return result.infrastructureAsCodeIssues
      .filter(issue => !issue.isIgnored)
      .map(issue => ({
        id: issue.id,
        title: issue.title,
        severity: this.normalizeSeverity(issue.severity),
        resource: issue.resource || 'unknown',
        path: issue.path,
        filePath: issue.cloudConfigPath[0] || 'unknown',
        line: 1,
        description: issue.msg,
        impact: issue.impact,
        resolve: issue.resolve,
        references: issue.references,
      }));
  }

  private normalizeSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'critical';
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
        return 'low';
      default:
        return 'medium';
    }
  }
}