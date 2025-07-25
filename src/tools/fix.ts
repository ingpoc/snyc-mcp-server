import { executeCommand, buildSnykCommand } from '../utils/exec.js';
import type { SnykFixResult, SnykConfig } from '../types/snyk.js';
import type { SnykFixArgs } from '../types/mcp.js';

interface SnykFixCommandResult {
  successful: Array<{
    userMessage: string;
  }>;
  failed: Array<{
    userMessage: string;
    reason: string;
  }>;
}

export class SnykFixTool {
  constructor(private config: SnykConfig) {}

  async fix(args: SnykFixArgs): Promise<SnykFixResult> {
    const commandArgs = [args.path || '.'];
    
    if (args.dryRun) {
      commandArgs.push('--dry-run');
    }

    const command = buildSnykCommand('fix', commandArgs, {
      org: this.config.orgId,
      json: true,
    });

    const result = await executeCommand(command, {
      cwd: args.path || process.cwd(),
      env: {
        SNYK_TOKEN: this.config.apiToken,
        SNYK_ORG: this.config.orgId,
        ...(this.config.baseUrl && { SNYK_API: this.config.baseUrl }),
      },
    });

    try {
      const fixResult = JSON.parse(result.stdout) as SnykFixCommandResult;
      return this.parseFixResults(fixResult, result.exitCode === 0);
    } catch (error) {
      return {
        success: result.exitCode === 0,
        fixes: [],
        errors: [
          {
            message: result.stderr || result.stdout || 'Unknown error occurred during fix',
            code: result.exitCode.toString(),
          },
        ],
      };
    }
  }

  async getFixableIssues(path?: string): Promise<Array<{ id: string; type: string; packageName: string; from: string; to?: string }>> {
    const command = buildSnykCommand('test', [
      path || '.',
      '--json',
    ], {
      org: this.config.orgId,
    });

    const result = await executeCommand(command, {
      cwd: path || process.cwd(),
      env: {
        SNYK_TOKEN: this.config.apiToken,
        SNYK_ORG: this.config.orgId,
        ...(this.config.baseUrl && { SNYK_API: this.config.baseUrl }),
      },
    });

    if (result.exitCode !== 0 && result.exitCode !== 1) {
      return [];
    }

    try {
      const scanResult = JSON.parse(result.stdout);
      const fixableIssues: Array<{ id: string; type: string; packageName: string; from: string; to?: string }> = [];

      if (scanResult.vulnerabilities) {
        for (const vuln of scanResult.vulnerabilities) {
          if (vuln.isUpgradable && vuln.upgradePath && vuln.upgradePath.length > 1) {
            fixableIssues.push({
              id: vuln.id,
              type: 'upgrade',
              packageName: vuln.packageName || vuln.name,
              from: vuln.version,
              to: vuln.upgradePath[vuln.upgradePath.length - 1],
            });
          } else if (vuln.isPatchable && vuln.patches && vuln.patches.length > 0) {
            fixableIssues.push({
              id: vuln.id,
              type: 'patch',
              packageName: vuln.packageName || vuln.name,
              from: vuln.version,
              to: vuln.patches[0]?.version,
            });
          }
        }
      }

      return fixableIssues;
    } catch (error) {
      return [];
    }
  }

  private parseFixResults(result: SnykFixCommandResult, success: boolean): SnykFixResult {
    const fixes: SnykFixResult['fixes'] = [];
    const errors: SnykFixResult['errors'] = [];

    for (const successful of result.successful || []) {
      const fix = this.parseFixMessage(successful.userMessage);
      if (fix) {
        fixes.push(fix);
      }
    }

    for (const failed of result.failed || []) {
      errors.push({
        message: failed.userMessage || failed.reason,
      });
    }

    return {
      success: success && errors.length === 0,
      fixes,
      errors,
    };
  }

  private parseFixMessage(message: string): SnykFixResult['fixes'][0] | null {
    const upgradeMatch = message.match(/Upgraded (.+) from (.+) to (.+)/);
    if (upgradeMatch && upgradeMatch[1] && upgradeMatch[2] && upgradeMatch[3]) {
      return {
        type: 'upgrade',
        packageName: upgradeMatch[1],
        from: upgradeMatch[2],
        to: upgradeMatch[3],
        vulns: [], 
      };
    }

    const patchMatch = message.match(/Patched (.+) version (.+)/);
    if (patchMatch && patchMatch[1] && patchMatch[2]) {
      return {
        type: 'patch',
        packageName: patchMatch[1],
        from: patchMatch[2],
        to: patchMatch[2],
        vulns: [], 
      };
    }

    const pinMatch = message.match(/Pinned (.+) to (.+)/);
    if (pinMatch && pinMatch[1] && pinMatch[2]) {
      return {
        type: 'pin',
        packageName: pinMatch[1],
        from: 'unknown',
        to: pinMatch[2],
        vulns: [], 
      };
    }

    return null;
  }
}