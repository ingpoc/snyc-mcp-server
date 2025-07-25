import { stat } from 'fs/promises';
import { resolve, join } from 'path';

export function sanitizePath(userPath: string, basePath: string = process.cwd()): string {
  const resolvedPath = resolve(basePath, userPath);
  const normalizedBase = resolve(basePath);
  
  if (!resolvedPath.startsWith(normalizedBase)) {
    throw new Error('Path traversal attempt detected');
  }
  
  return resolvedPath;
}

export async function validatePath(path: string): Promise<void> {
  try {
    await stat(path);
  } catch (error) {
    throw new Error(`Invalid path: ${path} does not exist or is not accessible`);
  }
}

export function sanitizeEnvironmentVariable(value: string): string {
  return value.replace(/[\n\r\0]/g, '');
}

export function validateApiToken(token: string): boolean {
  if (!token || typeof token !== 'string') {
    return false;
  }
  
  if (token.length < 20) {
    return false;
  }
  
  if (!/^[a-zA-Z0-9\-_]+$/.test(token)) {
    return false;
  }
  
  return true;
}

export function validateOrgId(orgId: string): boolean {
  if (!orgId || typeof orgId !== 'string') {
    return false;
  }
  
  if (orgId.length < 3) {
    return false;
  }
  
  if (!/^[a-zA-Z0-9\-_.]+$/.test(orgId)) {
    return false;
  }
  
  return true;
}

export function redactSensitiveInfo(text: string): string {
  return text
    .replace(/snyk_token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?/gi, 'snyk_token=***')
    .replace(/api[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?/gi, 'api_token=***')
    .replace(/authorization:\s*bearer\s+([a-zA-Z0-9\-_\.]{20,})/gi, 'authorization: bearer ***')
    .replace(/x-api-key:\s*([a-zA-Z0-9\-_]{20,})/gi, 'x-api-key: ***');
}

export function validateContainerImage(image: string): boolean {
  if (!image || typeof image !== 'string') {
    return false;
  }
  
  const imageRegex = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?([:/][a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$/;
  
  if (!imageRegex.test(image)) {
    return false;
  }
  
  if (image.length > 255) {
    return false;
  }
  
  return true;
}

export class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  
  constructor(
    private maxRequests: number = 100,
    private windowMs: number = 60000 // 1 minute
  ) {}
  
  isAllowed(identifier: string): boolean {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }
    
    const userRequests = this.requests.get(identifier)!;
    
    const validRequests = userRequests.filter(timestamp => timestamp > windowStart);
    this.requests.set(identifier, validRequests);
    
    if (validRequests.length >= this.maxRequests) {
      return false;
    }
    
    validRequests.push(now);
    return true;
  }
  
  cleanup(): void {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    for (const [identifier, timestamps] of this.requests.entries()) {
      const validRequests = timestamps.filter(timestamp => timestamp > windowStart);
      if (validRequests.length === 0) {
        this.requests.delete(identifier);
      } else {
        this.requests.set(identifier, validRequests);
      }
    }
  }
}