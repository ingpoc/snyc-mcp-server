import type { SnykCodeIssue, SnykIacIssue, SnykContainerIssue, SnykScanResult } from '../types/snyk.js';

export interface OptimizedVulnerability {
  id: string;
  type: 'dependency' | 'code' | 'infrastructure' | 'container';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  file: string;
  line?: number;
  column?: number;
  description: string;
  cwe?: string[] | undefined;
  fixable: boolean;
  fixMethod: 'snyk_fix' | 'manual_code_change' | 'dependency_upgrade' | 'configuration_change';
  fixGuidance: string;
  impact: string;
}

export interface OptimizedScanResponse {
  summary: {
    totalIssues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    fixableBySnyk: number;
    requiresManualFix: number;
  };
  vulnerabilities: OptimizedVulnerability[];
  nextSteps: string[];
}

export class AIOptimizedResponseFormatter {
  
  static formatCodeScanResults(issues: SnykCodeIssue[]): OptimizedScanResponse {
    const vulnerabilities: OptimizedVulnerability[] = issues.map(issue => ({
      id: issue.id,
      type: 'code' as const,
      severity: issue.severity,
      title: issue.title,
      file: issue.filePath,
      line: issue.line,
      column: issue.column,
      description: issue.message,
      cwe: issue.cwe || undefined,
      fixable: (issue.fixExamples?.length || 0) > 0,
      fixMethod: 'manual_code_change' as const,
      fixGuidance: (issue.fixExamples?.length || 0) > 0 
        ? `Code changes required. See fix examples: ${issue.fixExamples?.[0]?.title}`
        : 'Manual code review and fix required based on security best practices.',
      impact: this.getSecurityImpact(issue.title, issue.cwe),
    }));

    const summary = this.generateSummary(vulnerabilities);
    const nextSteps = this.generateCodeScanNextSteps(vulnerabilities);

    return { summary, vulnerabilities, nextSteps };
  }

  static formatScaScanResults(result: SnykScanResult): OptimizedScanResponse {
    const vulnerabilities: OptimizedVulnerability[] = result.vulnerabilities.map(vuln => ({
      id: vuln.id,
      type: 'dependency' as const,
      severity: vuln.severity,
      title: vuln.title,
      file: vuln.from[0] || 'package.json',
      description: `${vuln.package || vuln.name}@${vuln.version}: ${vuln.title}`,
      cwe: undefined, // Will get CWE from vulnerability details if available
      fixable: vuln.isUpgradable || vuln.isPatchable || !!vuln.fixedIn?.length,
      fixMethod: (vuln.isUpgradable || vuln.isPatchable) ? 'snyk_fix' : 'dependency_upgrade',
      fixGuidance: this.getFixGuidance(vuln),
      impact: `CVSS ${vuln.cvssScore || 'N/A'}: Package vulnerability affects application security`,
    }));

    const summary = this.generateSummary(vulnerabilities);
    const nextSteps = this.generateScaNextSteps(vulnerabilities);

    return { summary, vulnerabilities, nextSteps };
  }

  static formatIacScanResults(issues: SnykIacIssue[]): OptimizedScanResponse {
    const vulnerabilities: OptimizedVulnerability[] = issues.map(issue => ({
      id: issue.id,
      type: 'infrastructure' as const,
      severity: issue.severity,
      title: issue.title,
      file: issue.filePath,
      line: issue.line,
      description: issue.description,
      fixable: true,
      fixMethod: 'configuration_change' as const,
      fixGuidance: issue.resolve || 'Review and update infrastructure configuration based on security best practices.',
      impact: issue.impact || 'Infrastructure security misconfiguration',
    }));

    const summary = this.generateSummary(vulnerabilities);
    const nextSteps = this.generateIacNextSteps(vulnerabilities);

    return { summary, vulnerabilities, nextSteps };
  }

  static formatContainerScanResults(issues: SnykContainerIssue[]): OptimizedScanResponse {
    const vulnerabilities: OptimizedVulnerability[] = issues.map(issue => ({
      id: issue.id,
      type: 'container' as const,
      severity: issue.severity,
      title: issue.title,
      file: `${issue.dockerBaseImage}:${issue.layer}`,
      description: `${issue.packageName}@${issue.version}: ${issue.title}`,
      fixable: issue.isUpgradable || issue.isPatchable || !!issue.fixedIn?.length,
      fixMethod: (issue.isUpgradable || issue.isPatchable) ? 'dependency_upgrade' : 'configuration_change',
      fixGuidance: this.getContainerFixGuidance(issue),
      impact: `Container package vulnerability affects image security`,
    }));

    const summary = this.generateSummary(vulnerabilities);
    const nextSteps = this.generateContainerNextSteps(vulnerabilities);

    return { summary, vulnerabilities, nextSteps };
  }

  private static generateSummary(vulnerabilities: OptimizedVulnerability[]) {
    const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
    const high = vulnerabilities.filter(v => v.severity === 'high').length;
    const medium = vulnerabilities.filter(v => v.severity === 'medium').length;
    const low = vulnerabilities.filter(v => v.severity === 'low').length;
    const fixableBySnyk = vulnerabilities.filter(v => v.fixMethod === 'snyk_fix').length;
    const requiresManualFix = vulnerabilities.length - fixableBySnyk;

    return {
      totalIssues: vulnerabilities.length,
      critical,
      high,
      medium,
      low,
      fixableBySnyk,
      requiresManualFix,
    };
  }

  private static generateCodeScanNextSteps(vulnerabilities: OptimizedVulnerability[]): string[] {
    const steps: string[] = [];
    
    const criticalHigh = vulnerabilities.filter(v => ['critical', 'high'].includes(v.severity));
    if (criticalHigh.length > 0) {
      steps.push(`1. PRIORITY: Fix ${criticalHigh.length} critical/high severity code vulnerabilities first`);
    }

    const hasInjection = vulnerabilities.some(v => 
      v.title.toLowerCase().includes('injection') || 
      v.cwe?.some(cwe => ['CWE-78', 'CWE-89', 'CWE-79'].includes(cwe))
    );
    if (hasInjection) {
      steps.push('⚠️  CRITICAL: Code injection vulnerabilities found - fix immediately before deployment');
    }

    steps.push('2. AI should make targeted code changes to fix vulnerabilities without affecting functionality');
    steps.push('3. Test changes to ensure no functionality is broken');
    steps.push('4. Run snyk_code_scan again to verify all vulnerabilities are resolved');
    
    return steps;
  }

  private static generateScaNextSteps(vulnerabilities: OptimizedVulnerability[]): string[] {
    const steps: string[] = [];
    
    const autoFixable = vulnerabilities.filter(v => v.fixMethod === 'snyk_fix').length;
    if (autoFixable > 0) {
      steps.push(`1. Run snyk_fix with dryRun=true to preview ${autoFixable} automatic dependency fixes`);
      steps.push(`2. If preview looks good, run snyk_fix with dryRun=false to apply fixes`);
    }

    const manualFixes = vulnerabilities.filter(v => v.fixMethod === 'dependency_upgrade').length;
    if (manualFixes > 0) {
      steps.push(`3. Manually update ${manualFixes} dependencies that require version upgrades`);
    }

    const noFix = vulnerabilities.filter(v => v.fixGuidance.includes('No fix available')).length;
    if (noFix > 0) {
      steps.push(`⚠️  ${noFix} vulnerabilities have no fix - consider alternative packages`);
    }

    steps.push('4. Re-run snyk_sca_scan after applying fixes to verify resolution');
    
    return steps;
  }

  private static generateIacNextSteps(vulnerabilities: OptimizedVulnerability[]): string[] {
    const steps: string[] = [];
    
    const criticalInfra = vulnerabilities.filter(v => v.severity === 'critical').length;
    if (criticalInfra > 0) {
      steps.push(`URGENT: Fix ${criticalInfra} critical infrastructure misconfigurations`);
    }

    steps.push('Update infrastructure configuration files based on fix guidance');
    steps.push('Test infrastructure changes in staging environment first');
    steps.push('Re-run snyk_iac_scan to verify configuration fixes');
    
    return steps;
  }

  private static getSecurityImpact(title: string, cwe?: string[]): string {
    const titleLower = title.toLowerCase();
    
    if (titleLower.includes('injection') || cwe?.includes('CWE-78')) {
      return 'Remote code execution possible - CRITICAL security risk';
    }
    if (titleLower.includes('xss') || cwe?.includes('CWE-79')) {
      return 'Cross-site scripting - user data compromise risk';
    }
    if (titleLower.includes('sql') || cwe?.includes('CWE-89')) {
      return 'SQL injection - database compromise risk';
    }
    if (titleLower.includes('path traversal')) {
      return 'File system access - sensitive data exposure risk';
    }
    if (titleLower.includes('format string')) {
      return 'Log injection - information disclosure risk';
    }
    
    return 'Security vulnerability - review and fix recommended';
  }

  private static getFixGuidance(vuln: any): string {
    if (vuln.isUpgradable) {
      const upgradeTo = vuln.fixedIn?.[0] || vuln.upgradePath?.[vuln.upgradePath.length - 1];
      return `AUTO-FIXABLE: Run snyk_fix to upgrade to ${upgradeTo || 'latest secure version'}`;
    }
    
    if (vuln.isPatchable) {
      return `AUTO-FIXABLE: Run snyk_fix to apply security patch`;
    }
    
    if (vuln.fixedIn?.length) {
      return `MANUAL FIX: Upgrade dependency to version ${vuln.fixedIn[0]} or higher`;
    }
    
    return 'NO FIX AVAILABLE: Consider alternative packages or vendor security patches';
  }

  private static getContainerFixGuidance(issue: SnykContainerIssue): string {
    if (issue.isUpgradable && issue.fixedIn?.length) {
      return `CONTAINER FIX: Upgrade base image or package to version ${issue.fixedIn[0]} or higher`;
    }
    
    if (issue.isPatchable) {
      return `CONTAINER FIX: Apply security patches to container image`;
    }
    
    if (issue.fixedIn?.length) {
      return `CONTAINER FIX: Update container base image to include fixed package version ${issue.fixedIn[0]}`;
    }
    
    return 'CONTAINER FIX: Consider alternative base image or contact vendor for security patches';
  }

  private static generateContainerNextSteps(vulnerabilities: OptimizedVulnerability[]): string[] {
    const steps: string[] = [];
    
    const criticalHigh = vulnerabilities.filter(v => ['critical', 'high'].includes(v.severity));
    if (criticalHigh.length > 0) {
      steps.push(`1. URGENT: Address ${criticalHigh.length} critical/high container vulnerabilities before deployment`);
    }

    const fixableIssues = vulnerabilities.filter(v => v.fixable).length;
    if (fixableIssues > 0) {
      steps.push(`2. Update base image or rebuild container with fixed package versions`);
    }

    const noFix = vulnerabilities.filter(v => v.fixGuidance.includes('alternative base image')).length;
    if (noFix > 0) {
      steps.push(`⚠️  ${noFix} vulnerabilities require alternative base image or vendor patches`);
    }

    steps.push('3. Re-scan container image after applying fixes to verify resolution');
    
    return steps;
  }
}