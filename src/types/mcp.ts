// Minimal MCP types for tool arguments (used by existing tool classes)
export interface SnykScanArgs {
  path?: string | undefined;
  severity?: 'low' | 'medium' | 'high' | 'critical' | undefined;
  json?: boolean | undefined;
}

export interface SnykCodeScanArgs {
  path?: string | undefined;
  severity?: 'low' | 'medium' | 'high' | 'critical' | undefined;
  sarif?: boolean | undefined;
}

export interface SnykIacScanArgs {
  path?: string | undefined;
  severity?: 'low' | 'medium' | 'high' | 'critical' | undefined;
  json?: boolean | undefined;
}

export interface SnykContainerScanArgs {
  image: string;
  severity?: 'low' | 'medium' | 'high' | 'critical' | undefined;
  json?: boolean | undefined;
}

export interface SnykFixArgs {
  path?: string | undefined;
  dryRun?: boolean | undefined;
}

export interface SnykRescanArgs {
  path?: string | undefined;
  compareWith?: string | undefined;
}