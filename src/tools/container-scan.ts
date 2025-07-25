import { executeCommand, buildSnykCommand } from '../utils/exec.js';
import type { SnykContainerIssue, SnykConfig } from '../types/snyk.js';
import type { SnykContainerScanArgs } from '../types/mcp.js';

interface SnykContainerScanResult {
  vulnerabilities: Array<{
    id: string;
    title: string;
    severity: string;
    packageName: string;
    version: string;
    fixedIn?: string[];
    isUpgradable: boolean;
    isPatchable: boolean;
    dockerfileInstruction?: string;
    dockerBaseImage?: string;
    description?: string;
    from?: string[];
    upgradePath?: string[];
  }>;
  dependencyCount: number;
  packageManager: string;
  summary: string;
  docker: {
    baseImage: string;
    binariesVulns: {
      issuesData: Record<string, any>;
      affectedPkgs: Record<string, any>;
    };
  };
}

export class SnykContainerTool {
  constructor(private config: SnykConfig) {}

  async scan(args: SnykContainerScanArgs): Promise<SnykContainerIssue[]> {
    const command = buildSnykCommand('container test', [
      args.image,
      ...(args.severity ? ['--severity-threshold', args.severity] : []),
    ], {
      org: this.config.orgId,
      json: args.json,
    });

    const result = await executeCommand(command, {
      env: {
        SNYK_TOKEN: this.config.apiToken,
        SNYK_ORG: this.config.orgId,
        ...(this.config.baseUrl && { SNYK_API: this.config.baseUrl }),
      },
    });

    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new Error(`Snyk Container scan failed: ${result.stderr || result.stdout}`);
    }

    if (result.stdout.includes('No vulnerabilities found') || result.stdout.trim() === '') {
      return [];
    }

    try {
      const scanResult = JSON.parse(result.stdout) as SnykContainerScanResult;
      return this.parseContainerResults(scanResult, args.image);
    } catch (error) {
      throw new Error(`Failed to parse Snyk Container scan results: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private parseContainerResults(result: SnykContainerScanResult, image: string): SnykContainerIssue[] {
    const issues: SnykContainerIssue[] = [];

    for (const vuln of result.vulnerabilities) {
      const issue: SnykContainerIssue = {
        id: vuln.id,
        title: vuln.title,
        severity: this.normalizeSeverity(vuln.severity),
        packageName: vuln.packageName,
        version: vuln.version,
        fixedIn: vuln.fixedIn,
        isUpgradable: vuln.isUpgradable,
        isPatchable: vuln.isPatchable,
        layer: this.extractLayerInfo(vuln.from),
        dockerfileInstruction: vuln.dockerfileInstruction,
        dockerBaseImage: vuln.dockerBaseImage || result.docker?.baseImage || image,
      };

      issues.push(issue);
    }

    return issues;
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

  private extractLayerInfo(from?: string[]): string {
    if (!from || from.length === 0) {
      return 'unknown';
    }
    return from[0] || 'unknown';
  }
}