#!/usr/bin/env node

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';

const HELPER_DIR = path.join(os.homedir(), '.cc-custom-helper');
const HELPER_CONFIG_PATH = path.join(HELPER_DIR, 'config.json');
const CLAUDE_SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');
const CLAUDE_MCP_PATH = path.join(os.homedir(), '.claude.json');

const MANAGED_ENV_KEYS = [
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_MODEL',
  'ANTHROPIC_DEFAULT_OPUS_MODEL',
  'ANTHROPIC_DEFAULT_SONNET_MODEL',
  'ANTHROPIC_DEFAULT_HAIKU_MODEL',
  'API_TIMEOUT_MS',
  'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'
];

function printHelp() {
  console.log(`
cc-custom-helper - configure Claude Code for custom server

Usage:
  node cc-custom-helper.mjs <command> [options]

Commands:
  setup      Save config + write Claude Code env
  refresh    Update Claude Code + re-apply config
  validate   Validate endpoint and token
  status     Show helper and Claude Code status
  unset      Remove helper-managed env from Claude settings
  help       Show this help

Options:
  --base-url <url>             Custom server base URL, e.g. http://localhost:20128/v1
  --api-key <token>            API token
  --model <id>                 Runtime model id for Claude Code + validation (default: sonnet)
  --alias-opus <id>            Optional mapping for alias opus
  --alias-sonnet <id>          Optional mapping for alias sonnet
  --alias-haiku <id>           Optional mapping for alias haiku
  --validate-mode <mode>       anthropic | openai | chat | none (default: anthropic)
  --timeout-ms <num>           Request timeout in ms (default: 30000)
  --disable-nonessential <0|1> CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC (default: 1)
  --skip-validate              Skip validation during setup
  --skip-update                Skip Claude Code update during refresh
`);
}

function parseArgs(argv) {
  const command = argv[2] ?? 'help';
  const options = {};
  for (let i = 3; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      options[key] = true;
      continue;
    }
    options[key] = next;
    i += 1;
  }
  return { command, options };
}

function ensureDirFor(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function readJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return fallback;
  }
}

function writeJson(filePath, data) {
  ensureDirFor(filePath);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

function normalizeBaseUrl(baseUrl) {
  return baseUrl.replace(/\/+$/, '');
}

function getPersistedConfig() {
  return readJson(HELPER_CONFIG_PATH, {});
}

function savePersistedConfig(config) {
  ensureDirFor(HELPER_CONFIG_PATH);
  writeJson(HELPER_CONFIG_PATH, config);
}

function resolveConfig(options) {
  const persisted = getPersistedConfig();
  const baseUrl = options['base-url'] ?? persisted.baseUrl;
  const apiKey = options['api-key'] ?? persisted.apiKey;
  const model = options.model ?? persisted.model ?? 'sonnet';
  const validateMode = options['validate-mode'] ?? persisted.validateMode ?? 'anthropic';
  const aliasOpus = options['alias-opus'] ?? persisted.aliasOpus ?? '';
  const aliasSonnet = options['alias-sonnet'] ?? persisted.aliasSonnet ?? '';
  const aliasHaiku = options['alias-haiku'] ?? persisted.aliasHaiku ?? '';
  const timeoutMs = Number(options['timeout-ms'] ?? persisted.timeoutMs ?? 30000);
  const disableNonessential =
    String(options['disable-nonessential'] ?? persisted.disableNonessential ?? '1') === '0' ? '0' : '1';

  if (!baseUrl || !apiKey) {
    throw new Error('Missing required config: --base-url and --api-key (or previously saved config).');
  }

  return {
    baseUrl: normalizeBaseUrl(baseUrl),
    apiKey,
    model,
    validateMode,
    aliasOpus,
    aliasSonnet,
    aliasHaiku,
    timeoutMs,
    disableNonessential
  };
}

function ensureOnboardingCompleted() {
  const mcpConfig = readJson(CLAUDE_MCP_PATH, {});
  if (mcpConfig.hasCompletedOnboarding !== true) {
    writeJson(CLAUDE_MCP_PATH, { ...mcpConfig, hasCompletedOnboarding: true });
  }
}

function applyClaudeSettings(config) {
  const currentSettings = readJson(CLAUDE_SETTINGS_PATH, {});
  const currentEnv = currentSettings.env ?? {};
  const nextEnv = { ...currentEnv };

  delete nextEnv.ANTHROPIC_API_KEY;
  nextEnv.ANTHROPIC_AUTH_TOKEN = config.apiKey;
  nextEnv.ANTHROPIC_BASE_URL = config.baseUrl;
  nextEnv.ANTHROPIC_MODEL = config.model;

  if (config.aliasOpus) nextEnv.ANTHROPIC_DEFAULT_OPUS_MODEL = config.aliasOpus;
  else delete nextEnv.ANTHROPIC_DEFAULT_OPUS_MODEL;
  if (config.aliasSonnet) nextEnv.ANTHROPIC_DEFAULT_SONNET_MODEL = config.aliasSonnet;
  else delete nextEnv.ANTHROPIC_DEFAULT_SONNET_MODEL;
  if (config.aliasHaiku) nextEnv.ANTHROPIC_DEFAULT_HAIKU_MODEL = config.aliasHaiku;
  else delete nextEnv.ANTHROPIC_DEFAULT_HAIKU_MODEL;

  nextEnv.API_TIMEOUT_MS = String(config.timeoutMs);
  nextEnv.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = Number(config.disableNonessential);
  writeJson(CLAUDE_SETTINGS_PATH, { ...currentSettings, env: nextEnv });
}

async function runValidation(config) {
  if (config.validateMode === 'none') {
    return { ok: true, mode: 'none', details: 'validation disabled' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  const headers = {
    Authorization: `Bearer ${config.apiKey}`,
    'Content-Type': 'application/json'
  };
  try {
    const target =
      config.validateMode === 'openai' ? '/models' :
      config.validateMode === 'chat' ? '/chat/completions' : '/messages';
    const method = config.validateMode === 'openai' ? 'GET' : 'POST';
    const body = method === 'GET' ? undefined : JSON.stringify({
      model: config.model,
      max_tokens: 1,
      messages: [{ role: 'user', content: 'ping' }],
      stream: false
    });
    const res = await fetch(`${config.baseUrl}${target}`, { method, headers, body, signal: controller.signal });
    clearTimeout(timer);
    return { ok: res.ok, mode: config.validateMode, status: res.status, details: `${method} ${target} -> ${res.status}` };
  } catch (error) {
    clearTimeout(timer);
    return { ok: false, mode: config.validateMode, details: `request failed: ${error instanceof Error ? error.message : String(error)}` };
  }
}

async function main() {
  const { command, options } = parseArgs(process.argv);
  if (command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return;
  }
  if (command === 'setup') {
    const config = resolveConfig(options);
    if (!options['skip-validate']) {
      const result = await runValidation(config);
      if (!result.ok) {
        console.error(`Validation failed (${result.mode}): ${result.details}`);
        process.exitCode = 1;
        return;
      }
      console.log(`Validation OK (${result.mode}): ${result.details}`);
    }
    savePersistedConfig(config);
    ensureOnboardingCompleted();
    applyClaudeSettings(config);
    console.log('Claude Code configured for custom server.');
    return;
  }
  if (command === 'refresh') {
    const config = resolveConfig(options);
    if (!options['skip-update']) {
      execSync('npm install -g @anthropic-ai/claude-code', { stdio: 'inherit' });
    }
    savePersistedConfig(config);
    ensureOnboardingCompleted();
    applyClaudeSettings(config);
    console.log('Claude Code updated and reconfigured for custom server.');
    return;
  }
  if (command === 'status') {
    const persisted = getPersistedConfig();
    console.log(`baseUrl: ${persisted.baseUrl ?? '(not set)'}`);
    return;
  }
  if (command === 'unset') {
    const currentSettings = readJson(CLAUDE_SETTINGS_PATH, {});
    if (currentSettings.env) {
      const nextEnv = { ...currentSettings.env };
      for (const key of MANAGED_ENV_KEYS) delete nextEnv[key];
      if (Object.keys(nextEnv).length === 0) delete currentSettings.env;
      else currentSettings.env = nextEnv;
      writeJson(CLAUDE_SETTINGS_PATH, currentSettings);
    }
    console.log('Helper-managed Claude env keys removed.');
    return;
  }
  if (command === 'validate') {
    const config = resolveConfig(options);
    const result = await runValidation(config);
    if (!result.ok) {
      console.error(`Validation failed (${result.mode}): ${result.details}`);
      process.exitCode = 1;
      return;
    }
    console.log(`Validation OK (${result.mode}): ${result.details}`);
    return;
  }
  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exitCode = 1;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
