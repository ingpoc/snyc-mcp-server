import { executeCommand, buildSnykCommand } from '../utils/exec.js';
import type { SnykScanResult, SnykConfig } from '../types/snyk.js';
import type { SnykScanArgs } from '../types/mcp.js';

export class SnykScaTool {
  constructor(private config: SnykConfig) {}

  async scan(args: SnykScanArgs): Promise<SnykScanResult> {
    const command = buildSnykCommand('test', [
      args.path || '.',
      ...(args.severity ? ['--severity-threshold', args.severity] : []),
    ], {
      org: this.config.orgId, // buildSnykCommand handles undefined org gracefully
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
      throw new Error(`Snyk SCA scan failed: ${result.stderr || result.stdout}`);
    }

    try {
      const scanResult = JSON.parse(result.stdout) as SnykScanResult;
      return scanResult;
    } catch (error) {
      if (result.stdout.includes('No vulnerabilities found')) {
        return {
          ok: true,
          vulnerabilities: [],
          dependencyCount: 0,
          org: this.config.orgId || 'default',
          policy: '',
          isPrivate: true,
          licensesPolicy: null,
          packageManager: 'unknown',
          ignoreSettings: null,
          summary: 'No vulnerabilities found',
          filesystemPolicy: false,
          filtered: { ignore: [], patch: [] },
          uniqueCount: 0,
          projectName: 'unknown',
        };
      }
      throw new Error(`Failed to parse Snyk SCA scan results: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}