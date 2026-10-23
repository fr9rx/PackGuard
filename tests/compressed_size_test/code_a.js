'use strict';

const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const DEFAULT_OPTIONS = {
  configFile: 'app.config.json',
  encoding: 'utf8',
  retries: 3,
  retryDelay: 250,
  watch: false,
  env: process.env.NODE_ENV || 'development',
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deepMerge(target, source) {
  const output = { ...target };
  for (const key of Object.keys(source)) {
    const targetValue = output[key];
    const sourceValue = source[key];
    if (isPlainObject(targetValue) && isPlainObject(sourceValue)) {
      output[key] = deepMerge(targetValue, sourceValue);
    } else if (Array.isArray(targetValue) && Array.isArray(sourceValue)) {
      output[key] = targetValue.concat(sourceValue);
    } else {
      output[key] = sourceValue;
    }
  }
  return output;
}

function parseArgs(argv) {
  const result = { flags: {}, positional: [] };
  for (let index = 0; index < argv.length; index++) {
    const token = argv[index];
    if (token.startsWith('--')) {
      const [name, inlineValue] = token.slice(2).split('=');
      if (inlineValue !== undefined) {
        result.flags[name] = inlineValue;
      } else if (argv[index + 1] && !argv[index + 1].startsWith('-')) {
        result.flags[name] = argv[index + 1];
        index++;
      } else {
        result.flags[name] = true;
      }
    } else if (token.startsWith('-') && token.length > 1) {
      for (const letter of token.slice(1)) {
        result.flags[letter] = true;
      }
    } else {
      result.positional.push(token);
    }
  }
  return result;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function retry(task, retries, retryDelay) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await task(attempt);
    } catch (error) {
      lastError = error;
      if (attempt < retries) {
        await sleep(retryDelay * Math.pow(2, attempt));
      }
    }
  }
  throw lastError;
}

function formatBytes(bytes, decimals = 1) {
  if (bytes === 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value.toFixed(decimals)} ${units[exponent]}`;
}

function debounce(callback, wait) {
  let timer = null;
  return function debounced(...args) {
    if (timer) {
      clearTimeout(timer);
    }
    timer = setTimeout(() => {
      timer = null;
      callback.apply(this, args);
    }, wait);
  };
}

class ConfigLoader extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = deepMerge(DEFAULT_OPTIONS, options);
    this.config = {};
    this.watcher = null;
  }

  resolvePath() {
    return path.resolve(process.cwd(), this.options.configFile);
  }

  async readFile(filePath) {
    return retry(
      () => fs.promises.readFile(filePath, this.options.encoding),
      this.options.retries,
      this.options.retryDelay,
    );
  }

  async load() {
    const filePath = this.resolvePath();
    const raw = await this.readFile(filePath);
    const parsed = JSON.parse(raw);
    const base = parsed.default || {};
    const overrides = parsed[this.options.env] || {};
    this.config = deepMerge(base, overrides);
    this.emit('loaded', { filePath, size: formatBytes(Buffer.byteLength(raw)) });
    if (this.options.watch && !this.watcher) {
      this.startWatching(filePath);
    }
    return this.config;
  }

  startWatching(filePath) {
    const reload = debounce(() => {
      this.load()
        .then((config) => this.emit('reloaded', config))
        .catch((error) => this.emit('error', error));
    }, 100);
    this.watcher = fs.watch(filePath, reload);
  }

  get(key, fallback) {
    const parts = key.split('.');
    let current = this.config;
    for (const part of parts) {
      if (!isPlainObject(current) || !(part in current)) {
        return fallback;
      }
      current = current[part];
    }
    return current;
  }

  close() {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    this.removeAllListeners();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const loader = new ConfigLoader({
    configFile: args.flags.config || DEFAULT_OPTIONS.configFile,
    watch: Boolean(args.flags.watch || args.flags.w),
  });
  loader.on('loaded', (info) => console.log(`loaded ${info.filePath} (${info.size})`));
  loader.on('error', (error) => console.error(error.message));
  const config = await loader.load();
  for (const key of args.positional) {
    console.log(`${key} = ${JSON.stringify(loader.get(key, null))}`);
  }
  if (!loader.options.watch) {
    loader.close();
  }
  return config;
}

module.exports = { ConfigLoader, deepMerge, parseArgs, retry, formatBytes, debounce };

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
