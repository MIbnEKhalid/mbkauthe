#!/usr/bin/env node

/**
 * Setup script for git hooks
 * Run this after cloning the repository to install pre-commit hooks
 * Usage: node scripts/setup-hooks.js
 */

import { execSync } from 'child_process';

console.log('⚙️  Setting up git hooks...\n');

try {
  // Configure git to use the scripts directory
  execSync('git config core.hooksPath scripts', {
    stdio: 'inherit'
  });
  
  console.log('✅ Git hooks configured successfully!\n');
  console.log('Pre-commit hook will now run tests before each commit.\n');
  
  process.exit(0);
} catch (error) {
  console.error('❌ Failed to setup git hooks');
  console.error(error.message);
  process.exit(1);
}
