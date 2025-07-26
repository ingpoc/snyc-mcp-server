import { executeCommand, buildSnykCommand } from '../utils/exec.js';
import { ProjectDetector } from '../utils/project-detector.js';
import type { SnykScanResult, SnykConfig } from '../types/snyk.js';
import type { SnykScanArgs } from '../types/mcp.js';

export class SnykScaTool {
  private detector = new ProjectDetector();
  
  constructor(private config: SnykConfig) {}

  async scan(args: SnykScanArgs): Promise<SnykScanResult> {
    const scanPath = args.path || '.';
    
    // Check if project has dependencies before scanning
    const detection = await this.detector.detectProject(scanPath);
    if (!detection.hasDependencies) {
      throw new Error(`No dependency files found in '${scanPath}'. SCA scan requires package files like package.json, requirements.txt, Gemfile, etc. Found files: ${detection.dependencyFiles.length === 0 ? 'none' : detection.dependencyFiles.join(', ')}`);
    }
    const command = buildSnykCommand('test', [
      args.path || '.',
      ...(args.severity ? [`--severity-threshold=${args.severity}`] : []),
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
      // Provide specific error messages for common failures
      const errorOutput = result.stderr || result.stdout;
      if (errorOutput.includes('No supported package files')) {
        throw new Error(`No supported dependency files found. SCA scan requires files like package.json, requirements.txt, Gemfile, etc. in '${scanPath}'`);
      } else if (errorOutput.includes('Not authorised')) {
        throw new Error('Authentication failed. Please run snyk_auth_status to check authentication or contact your Snyk administrator for access.');
      } else if (errorOutput.includes('Missing option')) {
        throw new Error(`Snyk command error: ${errorOutput}. Check scan parameters and try again.`);
      } else {
        throw new Error(`Snyk SCA scan failed: ${errorOutput}`);
      }
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