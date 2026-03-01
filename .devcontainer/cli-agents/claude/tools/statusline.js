#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');

const E = '\u001b';
const colors = {
  blue: `${E}[38;2;0;153;255m`,
  orange: `${E}[38;2;255;176;85m`,
  green: `${E}[38;2;0;160;0m`,
  cyan: `${E}[38;2;100;200;200m`,
  red: `${E}[38;2;255;85;85m`,
  yellow: `${E}[38;2;230;200;0m`,
  white: `${E}[38;2;220;220;220m`,
  gray: `${E}[38;2;180;180;180m`,
  purple: `${E}[38;2;167;107;206m`,
  dkgreen: `${E}[38;2;0;120;0m`,
  dkyellow: `${E}[38;2;80;80;0m`,
  dkred: `${E}[38;2;180;50;50m`,
  dim: `${E}[2m`,
  reset: `${E}[0m`,
};

const sep = ` ${colors.dim}|${colors.reset} `;

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(''));
  });
}

function buildBar(pct, width) {
  let value = Number(pct);
  if (!Number.isFinite(value)) value = 0;
  if (value < 0) value = 0;
  if (value > 100) value = 100;

  const filled = Math.round((value * width) / 100);
  const empty = width - filled;

  let barColor = colors.green;
  if (value >= 75) barColor = colors.red;
  else if (value >= 50) barColor = colors.yellow;

  const filledStr = filled > 0 ? '●'.repeat(filled) : '';
  const emptyStr = empty > 0 ? '○'.repeat(empty) : '';

  return `${barColor}${filledStr}${colors.dim}${emptyStr}${colors.reset}`;
}

function visibleLength(text) {
  return String(text).replace(/\x1b\[[^m]*m/g, '').length;
}

function padColumn(text, visibleLen, colWidth) {
  const padding = colWidth - visibleLen;
  return padding > 0 ? text + ' '.repeat(padding) : text;
}

function formatResetTime(isoString, style) {
  if (!isoString) return '';

  try {
    const dt = new Date(isoString);
    if (Number.isNaN(dt.getTime())) return '';

    const hh = String(dt.getHours()).padStart(2, '0');
    const mm = String(dt.getMinutes()).padStart(2, '0');

    if (style === 'time') {
      return `${hh}:${mm}`;
    }

    const month = new Intl.DateTimeFormat('en-US', { month: 'short' }).format(dt);
    const day = dt.getDate();

    if (style === 'datetime') {
      return `${month} ${day}, ${hh}:${mm}`.toLowerCase();
    }

    return `${month} ${day}`.toLowerCase();
  } catch {
    return '';
  }
}

function readJsonFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function writeJsonFile(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data));
  } catch {
    // ignore cache write errors
  }
}

function getEffortLevel() {
  const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
  const settings = readJsonFile(settingsPath);

  let thinkingOn = false;
  let effortLevel = '';

  if (settings) {
    thinkingOn = settings.alwaysThinkingEnabled === true;
    const hasModel = settings.model !== null && settings.model !== undefined && settings.model !== '';
    if (hasModel) {
      effortLevel = '';
    } else if (settings.effortLevel) {
      effortLevel = settings.effortLevel;
    } else {
      effortLevel = 'medium';
    }
  }

  return { thinkingOn, effortLevel };
}

async function fetchUsageData() {
  const cacheFile = path.join(os.tmpdir(), 'claude-statusline-usage-cache.json');
  const cacheMaxAgeSeconds = 60;

  let usageData = null;
  let needsRefresh = true;

  if (fs.existsSync(cacheFile)) {
    try {
      const stat = fs.statSync(cacheFile);
      const ageSeconds = (Date.now() - stat.mtimeMs) / 1000;
      if (ageSeconds < cacheMaxAgeSeconds) {
        const cached = readJsonFile(cacheFile);
        if (cached) {
          usageData = cached;
          needsRefresh = false;
        }
      }
    } catch {
      needsRefresh = true;
    }
  }

  if (needsRefresh) {
    try {
      const credsPath = path.join(os.homedir(), '.claude', '.credentials.json');
      const creds = readJsonFile(credsPath);
      const token = creds?.claudeAiOauth?.accessToken;

      if (token) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);

        try {
          const response = await fetch('https://api.anthropic.com/api/oauth/usage', {
            method: 'GET',
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`,
              'anthropic-beta': 'oauth-2025-04-20',
              'User-Agent': 'claude-code/2.1.34',
            },
            signal: controller.signal,
          });

          if (response.ok) {
            const json = await response.json();
            usageData = json;
            writeJsonFile(cacheFile, json);
          }
        } finally {
          clearTimeout(timeout);
        }
      }
    } catch {
      // use stale cache fallback below
    }

    if (!usageData && fs.existsSync(cacheFile)) {
      const fallback = readJsonFile(cacheFile);
      if (fallback) usageData = fallback;
    }
  }

  return usageData;
}

function roundNumber(value, digits = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  const p = 10 ** digits;
  return Math.round(n * p) / p;
}

async function main() {
  try {
    const inputText = await readStdin();
    if (!inputText) {
      process.stdout.write('Claude');
      return;
    }

    const json = JSON.parse(inputText);

    const modelName = json?.model?.display_name || 'Claude';

    const sizeRaw = Number(json?.context_window?.context_window_size);
    const size = sizeRaw === 0 || !Number.isFinite(sizeRaw) ? 200000 : Math.trunc(sizeRaw);

    const usage = json?.context_window?.current_usage;
    const inputTokens = Number(usage?.input_tokens) || 0;
    const cacheCreate = Number(usage?.cache_creation_input_tokens) || 0;
    const cacheRead = Number(usage?.cache_read_input_tokens) || 0;
    const current = inputTokens + cacheCreate + cacheRead;

    const pctUsed = size > 0 ? Math.round((current / size) * 100) : 0;

    const { effortLevel } = getEffortLevel();

    const barWidth = 15;
    const col1w = 30;
    const modelCol = 55;

    const ctxBar = buildBar(pctUsed, barWidth);
    const l1c1Vis = `context: ${'x'.repeat(barWidth)} ${pctUsed}%`;
    let l1c1 = `${colors.white}context:${colors.reset} ${ctxBar} ${colors.cyan}${pctUsed}%${colors.reset}`;
    l1c1 = padColumn(l1c1, l1c1Vis.length, col1w);

    const tokensLeft = size - current;
    const l1Left = `${l1c1}${sep}${colors.purple}${tokensLeft.toLocaleString('en-US')} left${colors.reset}`;
    const l1Right = `${colors.blue}${modelName}${colors.reset}`;
    const l1LeftLen = visibleLength(l1Left);
    let gap1 = modelCol - l1LeftLen;
    if (gap1 < 1) gap1 = 1;

    const line1 = `${l1Left}${' '.repeat(gap1)}${l1Right}`;

    const usageData = await fetchUsageData();

    let line2 = '';
    let line3 = '';

    if (usageData) {
      let fiveHourPct = 0;
      let fiveHourReset = '';
      if (usageData.five_hour && usageData.five_hour.utilization !== null && usageData.five_hour.utilization !== undefined) {
        fiveHourPct = Math.round(Number(usageData.five_hour.utilization) || 0);
        fiveHourReset = formatResetTime(usageData.five_hour.resets_at, 'time');
      }
      const fiveHourBar = buildBar(fiveHourPct, barWidth);

      const fhC1Vis = `current: ${'x'.repeat(barWidth)} ${fiveHourPct}%`;
      let fhC1 = `${colors.white}current:${colors.reset} ${fiveHourBar} ${colors.cyan}${fiveHourPct}%${colors.reset}`;
      fhC1 = padColumn(fhC1, fhC1Vis.length, col1w);
      const fhC2 = `${colors.gray}${fiveHourReset}${colors.reset}`;

      let sevenDayPct = 0;
      let sevenDayReset = '';
      if (usageData.seven_day && usageData.seven_day.utilization !== null && usageData.seven_day.utilization !== undefined) {
        sevenDayPct = Math.round(Number(usageData.seven_day.utilization) || 0);
        sevenDayReset = formatResetTime(usageData.seven_day.resets_at, 'datetime');
      }
      const sevenDayBar = buildBar(sevenDayPct, barWidth);

      const sdC1Vis = `weekly:  ${'x'.repeat(barWidth)} ${sevenDayPct}%`;
      let sdC1 = `${colors.white}weekly:${colors.reset}  ${sevenDayBar} ${colors.cyan}${sevenDayPct}%${colors.reset}`;
      sdC1 = padColumn(sdC1, sdC1Vis.length, col1w);
      const sdC2 = `${colors.gray}${sevenDayReset}${colors.reset}`;

      let extraStr = '';
      if (usageData.extra_usage && usageData.extra_usage.is_enabled) {
        const extraPct = Math.round(Number(usageData.extra_usage.utilization) || 0);
        const extraUsed = roundNumber((Number(usageData.extra_usage.used_credits) || 0) / 100, 2);
        const extraLimit = roundNumber((Number(usageData.extra_usage.monthly_limit) || 0) / 100, 2);
        const extraBar = buildBar(extraPct, barWidth);
        extraStr = `${sep}${colors.white}extra:${colors.reset} ${extraBar} ${colors.cyan}$${extraUsed}/$${extraLimit}${colors.reset}`;
      }

      let effortStr = '';
      if (effortLevel) {
        let effortColor = colors.gray;
        if (effortLevel === 'high') effortColor = colors.dkgreen;
        else if (effortLevel === 'medium') effortColor = colors.dkyellow;
        else if (effortLevel === 'low') effortColor = colors.dkred;

        effortStr = `${effortColor}${effortLevel} effort${colors.reset}`;
      }

      const l2Left = `${fhC1}${sep}${fhC2}`;
      const l2LeftLen = visibleLength(l2Left);
      let gap2 = modelCol - l2LeftLen;
      if (gap2 < 1) gap2 = 1;
      line2 = `${l2Left}${' '.repeat(gap2)}${effortStr}`;

      line3 = `${sdC1}${sep}${sdC2}${extraStr}`;
    }

    process.stdout.write(line1);
    if (line2) process.stdout.write(`\n${line2}`);
    if (line3) process.stdout.write(`\n${line3}`);
  } catch (err) {
    process.stdout.write(`Claude | Error: ${err}`);
  }
}

main();
