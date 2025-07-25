import { readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import type { SnykConfig, SnykScanResult, SnykCodeIssue, SnykIacIssue, SnykContainerIssue } from '../types/snyk.js';
import type { SnykRescanArgs } from '../types/mcp.js';
import { SnykScaTool } from './sca-scan.js';
import { SnykCodeTool } from './code-scan.js';
import { SnykIacTool } from './iac-scan.js';

interface RescanResult {
  current: {
    sca: SnykScanResult;
    code: SnykCodeIssue[];
    iac: SnykIacIssue[];
  };
  previous?: {
    sca: SnykScanResult;
    code: SnykCodeIssue[];
    iac: SnykIacIssue[];
  } | undefined;
  comparison?: {
    resolved: {
      sca: string[];
      code: string[];
      iac: string[];
    };
    new: {
      sca: string[];
      code: string[];
      iac: string[];
    };
    remaining: {
      sca: number;
      code: number;
      iac: number;
    };
  } | undefined;
}

export class SnykRescanTool {
  private scaTool: SnykScaTool;
  private codeTool: SnykCodeTool;
  private iacTool: SnykIacTool;

  constructor(private config: SnykConfig) {
    this.scaTool = new SnykScaTool(config);
    this.codeTool = new SnykCodeTool(config);
    this.iacTool = new SnykIacTool(config);
  }

  async rescan(args: SnykRescanArgs): Promise<RescanResult> {
    const scanPath = args.path || process.cwd();
    
    const currentResults = await this.performFullScan(scanPath);
    
    await this.saveResults(currentResults, scanPath);

    let previousResults: RescanResult['previous'];
    if (args.compareWith) {
      try {
        const previousData = await readFile(args.compareWith, 'utf-8');
        previousResults = JSON.parse(previousData);
      } catch (error) {
        console.warn(`Could not load previous results from ${args.compareWith}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    const result: RescanResult = {
      current: currentResults,
      previous: previousResults,
    };

    if (previousResults) {
      result.comparison = this.compareResults(currentResults, previousResults);
    }

    return result;
  }

  async saveCurrentResults(path?: string): Promise<string> {
    const scanPath = path || process.cwd();
    const results = await this.performFullScan(scanPath);
    const filename = await this.saveResults(results, scanPath);
    return filename;
  }

  private async performFullScan(path: string): Promise<RescanResult['current']> {
    const [scaResults, codeResults, iacResults] = await Promise.allSettled([
      this.scaTool.scan({ path, json: true }),
      this.codeTool.scan({ path, sarif: true }),
      this.iacTool.scan({ path, json: true }),
    ]);

    return {
      sca: scaResults.status === 'fulfilled' ? scaResults.value : this.getEmptyScaResult(),
      code: codeResults.status === 'fulfilled' ? codeResults.value : [],
      iac: iacResults.status === 'fulfilled' ? iacResults.value : [],
    };
  }

  private async saveResults(results: RescanResult['current'], scanPath: string): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = join(scanPath, `.snyk-scan-${timestamp}.json`);
    
    await writeFile(filename, JSON.stringify(results, null, 2), 'utf-8');
    
    return filename;
  }

  private compareResults(
    current: RescanResult['current'],
    previous: RescanResult['current']
  ): RescanResult['comparison'] {
    const comparison: RescanResult['comparison'] = {
      resolved: { sca: [], code: [], iac: [] },
      new: { sca: [], code: [], iac: [] },
      remaining: { sca: 0, code: 0, iac: 0 },
    };

    const currentScaIds = new Set(current.sca.vulnerabilities.map(v => v.id));
    const previousScaIds = new Set(previous.sca.vulnerabilities.map(v => v.id));
    comparison.resolved.sca = Array.from(previousScaIds).filter(id => !currentScaIds.has(id));
    comparison.new.sca = Array.from(currentScaIds).filter(id => !previousScaIds.has(id));
    comparison.remaining.sca = current.sca.vulnerabilities.length;

    const currentCodeIds = new Set(current.code.map(v => v.id));
    const previousCodeIds = new Set(previous.code.map(v => v.id));
    comparison.resolved.code = Array.from(previousCodeIds).filter(id => !currentCodeIds.has(id));
    comparison.new.code = Array.from(currentCodeIds).filter(id => !previousCodeIds.has(id));
    comparison.remaining.code = current.code.length;

    const currentIacIds = new Set(current.iac.map(v => v.id));
    const previousIacIds = new Set(previous.iac.map(v => v.id));
    comparison.resolved.iac = Array.from(previousIacIds).filter(id => !currentIacIds.has(id));
    comparison.new.iac = Array.from(currentIacIds).filter(id => !previousIacIds.has(id));
    comparison.remaining.iac = current.iac.length;

    return comparison;
  }

  private getEmptyScaResult(): SnykScanResult {
    return {
      ok: true,
      vulnerabilities: [],
      dependencyCount: 0,
      org: this.config.orgId,
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
}