import { promises as fs } from 'fs';
import path from 'path';

export interface ProjectDetectionResult {
  hasDependencies: boolean;
  hasIaC: boolean;
  hasCode: boolean;
  dependencyFiles: string[];
  iacFiles: string[];
  codeFiles: string[];
  packageManager?: string;
}

const DEPENDENCY_FILES = [
  'package.json',        // Node.js
  'requirements.txt',    // Python
  'Pipfile',            // Python (pipenv)
  'pyproject.toml',     // Python (poetry)
  'Gemfile',            // Ruby
  'Cargo.toml',         // Rust
  'go.mod',             // Go
  'pom.xml',            // Java (Maven)
  'build.gradle',       // Java (Gradle)
  'composer.json',      // PHP
  'pubspec.yaml',       // Dart/Flutter
  'mix.exs',            // Elixir
];

const IAC_FILES = [
  '*.tf',               // Terraform
  '*.tfvars',           // Terraform variables
  'Dockerfile',         // Docker
  'docker-compose.yml', // Docker Compose
  'docker-compose.yaml',
  '*.yml',              // Kubernetes/CloudFormation
  '*.yaml',             // Kubernetes/CloudFormation
  'Chart.yaml',         // Helm
  'values.yaml',        // Helm
  'serverless.yml',     // Serverless
  'serverless.yaml',
];

const CODE_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx',    // JavaScript/TypeScript
  '.py',                           // Python
  '.rb',                           // Ruby
  '.rs',                           // Rust
  '.go',                           // Go
  '.java', '.kt',                  // Java/Kotlin
  '.php',                          // PHP
  '.dart',                         // Dart
  '.ex', '.exs',                   // Elixir
  '.c', '.cpp', '.cc', '.cxx',     // C/C++
  '.cs',                           // C#
  '.swift',                        // Swift
];

export class ProjectDetector {
  async detectProject(projectPath: string = '.'): Promise<ProjectDetectionResult> {
    const result: ProjectDetectionResult = {
      hasDependencies: false,
      hasIaC: false,
      hasCode: false,
      dependencyFiles: [],
      iacFiles: [],
      codeFiles: [],
    };

    try {
      const files = await this.getAllFiles(projectPath, 2); // Max depth 2 to avoid deep recursion
      
      // Check for dependency files
      for (const file of files) {
        const fileName = path.basename(file);
        if (DEPENDENCY_FILES.includes(fileName)) {
          result.dependencyFiles.push(file);
          result.hasDependencies = true;
          
          // Determine package manager
          if (fileName === 'package.json') result.packageManager = 'npm';
          else if (fileName === 'requirements.txt') result.packageManager = 'pip';
          else if (fileName === 'Gemfile') result.packageManager = 'bundler';
          else if (fileName === 'Cargo.toml') result.packageManager = 'cargo';
          else if (fileName === 'go.mod') result.packageManager = 'go';
        }
      }

      // Check for IaC files
      for (const file of files) {
        const fileName = path.basename(file);
        const isIaC = IAC_FILES.some(pattern => {
          if (pattern.includes('*')) {
            const regex = new RegExp(pattern.replace('*', '.*'));
            return regex.test(fileName);
          }
          return pattern === fileName;
        });
        
        if (isIaC) {
          result.iacFiles.push(file);
          result.hasIaC = true;
        }
      }

      // Check for code files
      for (const file of files) {
        const ext = path.extname(file);
        if (CODE_EXTENSIONS.includes(ext)) {
          result.codeFiles.push(file);
          result.hasCode = true;
        }
      }

    } catch (error) {
      console.error(`Error detecting project structure: ${error}`);
    }

    return result;
  }

  private async getAllFiles(dir: string, maxDepth: number, currentDepth: number = 0): Promise<string[]> {
    if (currentDepth >= maxDepth) return [];
    
    const files: string[] = [];
    
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        // Skip node_modules, .git, and other common dirs
        if (entry.isDirectory() && !this.shouldSkipDirectory(entry.name)) {
          const subFiles = await this.getAllFiles(fullPath, maxDepth, currentDepth + 1);
          files.push(...subFiles);
        } else if (entry.isFile()) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      // Directory might not be accessible
    }
    
    return files;
  }

  private shouldSkipDirectory(dirName: string): boolean {
    const skipDirs = [
      'node_modules', '.git', '.svn', '.hg',
      'dist', 'build', 'target', '__pycache__',
      '.venv', 'venv', '.env', 'vendor',
      '.next', '.nuxt', 'coverage'
    ];
    return skipDirs.includes(dirName) || dirName.startsWith('.');
  }

  getRecommendations(detection: ProjectDetectionResult): string[] {
    const recommendations: string[] = [];
    
    if (detection.hasCode) {
      recommendations.push('snyk_code_scan - Static code analysis for security vulnerabilities');
    }
    
    if (detection.hasDependencies) {
      recommendations.push(`snyk_sca_scan - Dependency vulnerability scan (${detection.packageManager || 'detected package manager'})`);
    }
    
    if (detection.hasIaC) {
      recommendations.push('snyk_iac_scan - Infrastructure as Code security configuration scan');
    }
    
    if (!detection.hasCode && !detection.hasDependencies && !detection.hasIaC) {
      recommendations.push('No scannable files detected. This appears to be an empty or non-software project.');
    }
    
    return recommendations;
  }
}