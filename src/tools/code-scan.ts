import { executeCommand, buildSnykCommand } from '../utils/exec.js';
import type { SnykCodeScanResult, SnykCodeIssue, SnykConfig } from '../types/snyk.js';
import type { SnykCodeScanArgs } from '../types/mcp.js';

export class SnykCodeTool {
  constructor(private config: SnykConfig) {}

  async scan(args: SnykCodeScanArgs): Promise<SnykCodeIssue[]> {
    const command = buildSnykCommand('code test', [
      args.path || '.',
      ...(args.severity ? ['--severity-threshold', args.severity] : []),
    ], {
      org: this.config.orgId,
      sarif: args.sarif,
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
      throw new Error(`Snyk Code scan failed: ${result.stderr || result.stdout}`);
    }

    if (result.stdout.includes('No issues found') || result.stdout.trim() === '') {
      return [];
    }

    try {
      // Clean stdout to extract only the JSON part (ignore stderr that might be mixed in)
      let jsonOutput = result.stdout.trim();
      
      // If stdout starts with non-JSON content, try to find the JSON part
      if (!jsonOutput.startsWith('{')) {
        const jsonStart = jsonOutput.indexOf('{');
        if (jsonStart !== -1) {
          jsonOutput = jsonOutput.substring(jsonStart);
        }
      }
      
      const sarifResult = JSON.parse(jsonOutput) as SnykCodeScanResult;
      return this.parseSarifToCodeIssues(sarifResult);
    } catch (error) {
      throw new Error(`Failed to parse Snyk Code scan results: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private parseSarifToCodeIssues(sarif: SnykCodeScanResult): SnykCodeIssue[] {
    const issues: SnykCodeIssue[] = [];

    for (const run of sarif.runs) {
      const rules = new Map(run.tool.driver.rules.map(rule => [rule.id, rule]));

      for (const result of run.results) {
        const rule = rules.get(result.ruleId);
        if (!rule) continue;

        const location = result.locations[0]?.physicalLocation;
        if (!location) continue;

        const severity = this.mapSarifLevelToSeverity(result.level);
        const confidence = this.extractConfidenceFromRule(rule);

        const issue: SnykCodeIssue = {
          id: result.fingerprints['1'] || result.fingerprints['0'] || `${result.ruleId}-${location.region.startLine}`,
          title: rule.name,
          severity,
          confidence,
          filePath: location.artifactLocation.uri,
          line: location.region.startLine,
          lineEnd: location.region.endLine,
          column: location.region.startColumn,
          columnEnd: location.region.endColumn,
          message: result.message.text,
          rule: rule.name,
          ruleId: result.ruleId,
          cwe: rule.properties.cwe,
          fixExamples: rule.properties.exampleCommitFixes?.map(fix => ({
            title: `Example fix from commit ${fix.commitURL}`,
            description: 'Example fix based on real commit',
            code: fix.lines.filter(line => line.lineChange === 'added').map(line => line.line).join('\n'),
          })) || [],
        };

        issues.push(issue);
      }
    }

    return issues;
  }

  private mapSarifLevelToSeverity(level: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (level.toLowerCase()) {
      case 'error':
        return 'high';
      case 'warning':
        return 'medium';
      case 'info':
      case 'note':
        return 'low';
      default:
        return 'medium';
    }
  }

  private extractConfidenceFromRule(rule: any): 'low' | 'medium' | 'high' {
    const precision = rule.properties?.precision?.toLowerCase();
    switch (precision) {
      case 'very-high':
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
      default:
        return 'low';
    }
  }
}