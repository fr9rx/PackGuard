'use strict';

const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const DEFAULT_OPTIONS = {
  _0xa1d9File: 'app._0xa1d9.json',
  encoding: 'utf8',
  retries: 3,
  _0x1e93Delay: 250,
  watch: false,
  env: process.env.NODE_ENV || 'development',
};

function _0x6b0d(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function _0x3f1a(target, source) {
  const output = { ...target };
  for (const key of Object.keys(source)) {
    const targetValue = output[key];
    const sourceValue = source[key];
    if (_0x6b0d(targetValue) && _0x6b0d(sourceValue)) {
      output[key] = _0x3f1a(targetValue, sourceValue);
    } else if (Array.isArray(targetValue) && Array.isArray(sourceValue)) {
      output[key] = targetValue.concat(sourceValue);
    } else {
      output[key] = sourceValue;
    }
  }
  return output;
}

function _0x9b2c(argv) {
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

async function _0x1e93(task, retries, _0x1e93Delay) {
  let lastError;
  for (let _0xe5b4 = 0; _0xe5b4 <= retries; _0xe5b4++) {
    try {
      return await task(_0xe5b4);
    } catch (error) {
      lastError = error;
      if (_0xe5b4 < retries) {
        await sleep(_0x1e93Delay * Math.pow(2, _0xe5b4));
      }
    }
  }
  throw lastError;
}

function _0x2a6f(bytes, decimals = 1) {
  if (bytes === 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value.toFixed(decimals)} ${units[exponent]}`;
}

function _0x5c81(callback, wait) {
  let timer = null;
  return function _0x5c81d(...args) {
    if (timer) {
      clearTimeout(timer);
    }
    timer = setTimeout(() => {
      timer = null;
      callback.apply(this, args);
    }, wait);
  };
}

class _0x7d4e extends EventEmitter {
  constructor(_0x8c35 = {}) {
    super();
    this._0x8c35 = _0x3f1a(DEFAULT_OPTIONS, _0x8c35);
    this._0xa1d9 = {};
    this._0xc7f2 = null;
  }

  resolvePath() {
    return path.resolve(process.cwd(), this._0x8c35._0xa1d9File);
  }

  async readFile(_0x4f27) {
    return _0x1e93(
      () => fs.promises.readFile(_0x4f27, this._0x8c35.encoding),
      this._0x8c35.retries,
      this._0x8c35._0x1e93Delay,
    );
  }

  async load() {
    const _0x4f27 = this.resolvePath();
    const raw = await this.readFile(_0x4f27);
    const parsed = JSON.parse(raw);
    const base = parsed.default || {};
    const overrides = parsed[this._0x8c35.env] || {};
    this._0xa1d9 = _0x3f1a(base, overrides);
    this.emit('loaded', { _0x4f27, size: _0x2a6f(Buffer.byteLength(raw)) });
    if (this._0x8c35.watch && !this._0xc7f2) {
      this.startWatching(_0x4f27);
    }
    return this._0xa1d9;
  }

  startWatching(_0x4f27) {
    const reload = _0x5c81(() => {
      this.load()
        .then((_0xa1d9) => this.emit('reloaded', _0xa1d9))
        .catch((error) => this.emit('error', error));
    }, 100);
    this._0xc7f2 = fs.watch(_0x4f27, reload);
  }

  get(key, fallback) {
    const parts = key.split('.');
    let current = this._0xa1d9;
    for (const part of parts) {
      if (!_0x6b0d(current) || !(part in current)) {
        return fallback;
      }
      current = current[part];
    }
    return current;
  }

  close() {
    if (this._0xc7f2) {
      this._0xc7f2.close();
      this._0xc7f2 = null;
    }
    this.removeAllListeners();
  }
}

async function main() {
  const args = _0x9b2c(process.argv.slice(2));
  const _0xd3a8 = new _0x7d4e({
    _0xa1d9File: args.flags._0xa1d9 || DEFAULT_OPTIONS._0xa1d9File,
    watch: Boolean(args.flags.watch || args.flags.w),
  });
  _0xd3a8.on('loaded', (info) => console.log(`loaded ${info._0x4f27} (${info.size})`));
  _0xd3a8.on('error', (error) => console.error(error.message));
  const _0xa1d9 = await _0xd3a8.load();
  for (const key of args.positional) {
    console.log(`${key} = ${JSON.stringify(_0xd3a8.get(key, null))}`);
  }
  if (!_0xd3a8._0x8c35.watch) {
    _0xd3a8.close();
  }
  return _0xa1d9;
}

module.exports = { _0x7d4e, _0x3f1a, _0x9b2c, _0x1e93, _0x2a6f, _0x5c81 };

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
