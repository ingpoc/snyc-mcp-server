export interface SnykConfig {
  apiToken: string;
  orgId?: string | undefined;
  baseUrl?: string | undefined;
}

export interface SnykVulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore?: number;
  cwe?: string[];
  cve?: string[];
  exploitMaturity?: 'mature' | 'proof-of-concept' | 'no-known-exploit' | 'no-data';
  isPatchable: boolean;
  isUpgradable: boolean;
  from: string[];
  upgradePath: string[];
  semver?: {
    vulnerable: string[];
  };
  patches?: Array<{
    id: string;
    urls: string[];
    version: string;
    modificationTime: string;
  }>;
  publicationTime?: string;
  disclosureTime?: string;
  credit?: string[];
  identifiers?: {
    CVE?: string[];
    CWE?: string[];
  };
  references?: Array<{
    title: string;
    url: string;
  }>;
  fixedIn?: string[];
}

export interface SnykIssue {
  id: string;
  url: string;
  title: string;
  type: 'vuln' | 'license';
  paths: Array<{
    from: string[];
    upgrade: boolean;
    patch: boolean;
  }>;
  package: string;
  version: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  language: string;
  packageManager: string;
  semver: {
    vulnerable: string[];
  };
  publicationTime: string;
  disclosureTime: string;
  credit: string[];
  CVSSv3?: string;
  cvssScore?: number;
  patches?: Array<{
    version: string;
    id: string;
    urls: string[];
    modificationTime: string;
  }>;
  upgradePath: string[];
  isUpgradable: boolean;
  isPatchable: boolean;
  name: string;
  from: string[];
  fixedIn?: string[];
}

export interface SnykCodeIssue {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  filePath: string;
  line: number;
  lineEnd?: number;
  column: number;
  columnEnd?: number;
  message: string;
  rule: string;
  ruleId: string;
  cwe?: string[];
  owasp?: string[];
  fixExamples?: Array<{
    title: string;
    description: string;
    code: string;
  }>;
}

export interface SnykIacIssue {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  resource: string;
  path: string[];
  filePath: string;
  line: number;
  lineEnd?: number;
  description: string;
  impact: string;
  resolve: string;
  references?: string[] | undefined;
}

export interface SnykContainerIssue {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  packageName: string;
  version: string;
  fixedIn?: string[] | undefined;
  isUpgradable: boolean;
  isPatchable: boolean;
  layer: string;
  dockerfileInstruction?: string | undefined;
  dockerBaseImage?: string | undefined;
}

export interface SnykScanResult {
  ok: boolean;
  vulnerabilities: SnykIssue[];
  dependencyCount: number;
  org: string;
  policy: string;
  isPrivate: boolean;
  licensesPolicy: unknown;
  packageManager: string;
  ignoreSettings: unknown;
  summary: string;
  remediation?: {
    unresolved: SnykIssue[];
    upgrade: Record<string, {
      upgradeTo: string;
      upgrades: string[];
      vulns: string[];
    }>;
    patch: Record<string, {
      patched: string;
    }>;
    ignore: Record<string, unknown>;
    pin: Record<string, unknown>;
  };
  filesystemPolicy: boolean;
  filtered: {
    ignore: SnykIssue[];
    patch: SnykIssue[];
  };
  uniqueCount: number;
  projectName: string;
  foundProjectCount?: number;
}

export interface SnykCodeScanResult {
  runs: Array<{
    tool: {
      driver: {
        name: string;
        semanticVersion: string;
        version: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          help: { text: string; markdown: string };
          properties: {
            tags: string[];
            categories: string[];
            exampleCommitFixes: Array<{
              commitURL: string;
              lines: Array<{
                line: string;
                lineNumber: number;
                lineChange: 'added' | 'removed' | 'none';
              }>;
            }>;
            exampleCommitDescriptions: string[];
            precision: string;
            repoDatasetSize: number;
            cwe: string[];
          };
          defaultConfiguration: { level: string };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: string;
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: {
            startLine: number;
            endLine: number;
            startColumn: number;
            endColumn: number;
          };
        };
      }>;
      fingerprints: {
        '0': string;
        '1': string;
      };
      codeFlows: Array<{
        threadFlows: Array<{
          locations: Array<{
            location: {
              physicalLocation: {
                artifactLocation: { uri: string };
                region: {
                  startLine: number;
                  endLine: number;
                  startColumn: number;
                  endColumn: number;
                };
              };
              message: { text: string };
            };
          }>;
        }>;
      }>;
      properties: {
        priorityScore: number;
        priorityScoreFactors: Array<{
          label: string;
          type: string;
        }>;
      };
    }>;
  }>;
}

export interface SnykAuthStatus {
  authenticated: boolean;
  username?: string | undefined;
  userId?: string | undefined;
  orgId?: string | undefined;
  orgName?: string | undefined;
  apiUrl?: string | undefined;
}

export interface SnykFixResult {
  success: boolean;
  fixes: Array<{
    type: 'upgrade' | 'patch' | 'pin';
    packageName: string;
    from: string;
    to: string;
    vulns: string[];
  }>;
  errors: Array<{
    message: string;
    code?: string;
  }>;
}