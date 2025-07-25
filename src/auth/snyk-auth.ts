import { exec } from 'child_process';
import { promisify } from 'util';
import type { SnykConfig, SnykAuthStatus } from '../types/snyk.js';

const execAsync = promisify(exec);

export class SnykAuth {
  private config: SnykConfig | null = null;

  async authenticate(apiToken: string, orgId: string, baseUrl?: string): Promise<void> {
    try {
      // Set environment variables for Snyk CLI
      process.env.SNYK_TOKEN = apiToken;
      process.env.SNYK_ORG = orgId;
      if (baseUrl) {
        process.env.SNYK_API = baseUrl;
      }

      // Check if already authenticated
      const authStatus = await this.getAuthStatus();
      if (!authStatus.authenticated) {
        // Authenticate using snyk auth command with the API token
        console.log('Snyk not authenticated, performing automatic authentication...');
        await execAsync(`snyk auth ${apiToken}`);
        
        // Verify authentication worked
        const newAuthStatus = await this.getAuthStatus();
        if (!newAuthStatus.authenticated) {
          throw new Error('Automatic authentication failed. Please check your API token.');
        }
        console.log('Snyk authentication successful');
      }

      this.config = { apiToken, orgId, baseUrl };
    } catch (error) {
      throw new Error(`Snyk authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getAuthStatus(): Promise<SnykAuthStatus> {
    try {
      // First try to get API URL
      let apiUrl: string | undefined;
      try {
        const { stdout } = await execAsync('snyk config get api');
        apiUrl = stdout.trim();
      } catch {
        // Ignore if config get api fails
      }

      // Try whoami command to check authentication
      const { stdout: whoamiOutput } = await execAsync('snyk whoami --experimental');
      const lines = whoamiOutput.split('\n');
      
      let username: string | undefined;
      let userId: string | undefined;
      let orgId: string | undefined;
      let orgName: string | undefined;

      for (const line of lines) {
        const trimmedLine = line.trim();
        if (trimmedLine.startsWith('Username:')) {
          username = trimmedLine.replace('Username:', '').trim();
        } else if (trimmedLine.startsWith('User ID:')) {
          userId = trimmedLine.replace('User ID:', '').trim();
        } else if (trimmedLine.startsWith('Org:')) {
          const orgPart = trimmedLine.replace('Org:', '').trim();
          const orgMatch = orgPart.match(/^(.+)\s+\(([^)]+)\)$/);
          if (orgMatch) {
            orgName = orgMatch[1]?.trim();
            orgId = orgMatch[2]?.trim();
          } else {
            orgName = orgPart;
          }
        }
      }

      return {
        authenticated: true,
        username,
        userId,
        orgId: orgId || this.config?.orgId,
        orgName,
        apiUrl: apiUrl || this.config?.baseUrl,
      };
    } catch (error) {
      // If whoami fails, we're not authenticated
      return {
        authenticated: false,
      };
    }
  }

  isAuthenticated(): boolean {
    return this.config !== null;
  }

  getConfig(): SnykConfig | null {
    return this.config;
  }

  async validateSnykCli(): Promise<void> {
    try {
      await execAsync('snyk --version');
    } catch (error) {
      throw new Error('Snyk CLI is not installed or not accessible. Please install Snyk CLI first.');
    }
  }
}