import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface ExecOptions {
  cwd?: string;
  timeout?: number;
  env?: Record<string, string>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export async function executeCommand(
  command: string,
  options: ExecOptions = {}
): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execAsync(command, {
      cwd: options.cwd || process.cwd(),
      timeout: options.timeout || 300000, // 5 minutes default
      env: { ...process.env, ...options.env },
      maxBuffer: 1024 * 1024 * 10, // 10MB buffer
    });

    return {
      stdout: stdout.toString(),
      stderr: stderr.toString(),
      exitCode: 0,
    };
  } catch (error: any) {
    return {
      stdout: error.stdout?.toString() || '',
      stderr: error.stderr?.toString() || error.message,
      exitCode: error.code || 1,
    };
  }
}

export function buildSnykCommand(
  subcommand: string,
  args: string[] = [],
  options: { org?: string | undefined; json?: boolean | undefined; sarif?: boolean | undefined } = {}
): string {
  const parts = ['snyk', subcommand];
  
  // Add all args in order (they should already be correctly formatted)
  parts.push(...args);
  
  // Add options
  if (options.org) {
    parts.push('--org', options.org);
  }
  
  if (options.json) {
    parts.push('--json');
  }
  
  if (options.sarif) {
    parts.push('--sarif');
  }
  
  return parts.join(' ');
}