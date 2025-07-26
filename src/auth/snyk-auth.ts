import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import type { SnykConfig, SnykAuthStatus } from '../types/snyk.js';

const execAsync = promisify(exec);

/**
 * Snyk Authentication Flow:
 * 1. API Token (from env vars) -> Used to initiate OAuth
 * 2. snyk auth <API_TOKEN> -> Opens browser for user approval  
 * 3. User approves -> Snyk CLI stores session tokens locally
 * 4. Session tokens -> Used for all subsequent CLI commands
 */
export class SnykAuth {
  private config: SnykConfig | null = null;

  async authenticate(apiToken: string, orgId?: string, baseUrl?: string): Promise<void> {
    try {
      // Set base URL if provided
      if (baseUrl) {
        process.env.SNYK_API = baseUrl;
        await execAsync(`snyk config set api=${baseUrl}`);
      }

      // Check if already authenticated with valid session tokens
      const authStatus = await this.getAuthStatus();
      if (authStatus.authenticated) {
        console.log(`Snyk already authenticated as ${authStatus.username || 'user'} (${authStatus.orgName || authStatus.orgId || orgId})`);
        // Set environment variables for tools that might still need them
        process.env.SNYK_TOKEN = apiToken;
        if (orgId) {
          process.env.SNYK_ORG = orgId;
        }
        this.config = { apiToken, orgId, baseUrl };
        return;
      }

      // No valid session tokens found, need to authenticate
      console.log('No valid Snyk session found. Starting OAuth authentication flow...');
      console.log('Using API token to initiate OAuth flow...');
      console.log('A browser window will open for you to approve the authentication.');
      console.log('Please complete the authentication in your browser.');
      
      // Use the API token to initiate OAuth flow which creates session tokens
      await this.runSnykAuthWithBrowser(apiToken);
      
      // Wait for authentication to complete and tokens to be stored
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      // Verify OAuth authentication worked and session tokens are now available
      const newAuthStatus = await this.getAuthStatus();
      if (!newAuthStatus.authenticated) {
        throw new Error('OAuth authentication failed. Please ensure you completed the browser authentication flow and granted access.');
      }
      
      console.log(`OAuth authentication successful! Session tokens stored for ${newAuthStatus.username || 'user'}`);
      
      // Set environment variables for any tools that might still need the original API token
      process.env.SNYK_TOKEN = apiToken;
      if (orgId) {
        process.env.SNYK_ORG = orgId;
      }
      
      this.config = { apiToken, orgId, baseUrl };
    } catch (error) {
      if (error instanceof Error && error.message.includes('timeout')) {
        throw new Error('Authentication timed out. Please try again and complete the browser authentication within 2 minutes.');
      }
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

  private async runSnykAuthWithBrowser(apiToken: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const authProcess = spawn('snyk', ['auth', apiToken], {
        stdio: 'inherit',
        shell: true
      });

      const timeout = setTimeout(() => {
        authProcess.kill();
        reject(new Error('Authentication timed out after 2 minutes'));
      }, 120000); // 2 minutes

      authProcess.on('exit', (code) => {
        clearTimeout(timeout);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Authentication failed with exit code ${code}`));
        }
      });

      authProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }
}