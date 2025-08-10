'use strict';
require('dotenv').config();
/**
 * Secure AES file encryption/decryption API (Koyeb-friendly, streaming)
 *
 * Endpoints:
 *   POST /encrypt  (multipart/form-data: file, mode, passphrase|key_b64, [aad_b64])
 *   POST /decrypt  (multipart/form-data: file, passphrase|key_b64, [aad_b64])
 *   GET  /health   (JSON: { status: 'ok' })
 *
 * Security:
 * - API key auth via x-api-key or Authorization: Bearer <key>
 * - Per-key rate limiting
 * - HTTPS enforced via proxy headers (Koyeb terminates TLS)
 *
 * AES modes supported:
 * - aes-256-gcm (AEAD)
 * - aes-256-cbc
 * - aes-256-ctr
 *
 * Envelope formats:
 * - AES2 (streaming-friendly): [ "AES2"(4) | mode(1) | ivLen(1) | saltLen(1) | tagLen(1) | IV | SALT | CIPHERTEXT | TAG ]
 * - AES1 (legacy accepted on decrypt): [ "AES1"(4) | mode(1) | ivLen(1) | saltLen(1) | tagLen(1) | IV | SALT | TAG | CIPHERTEXT ]
 *
 * Notes:
 * - Encryption is fully streamed.
 * - Decrypt (CBC/CTR) is streamed to client.
 * - Decrypt (GCM) writes plaintext to a temp file until authentication succeeds, then streams it to client (prevents leaking unauthenticated plaintext).
 */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Busboy = require('busboy');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  PORT = '8080',
  API_KEYS = `${process.env.API_KEY}`,
  MAX_FILE_MB = '1024',
  RATE_WINDOW_MS = `${15 * 60 * 1000}`,
  RATE_MAX = '100',
  ENFORCE_HTTPS = 'true'
} = process.env;

const app = express();
app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);
app.use(
  helmet.hsts({
    maxAge: 15552000,
    includeSubDomains: true,
    preload: false
  })
);

if (ENFORCE_HTTPS !== 'false') {
  app.use((req, res, next) => {
    const xfProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    if (xfProto && xfProto !== 'https') {
      return res.redirect(308, `https://${req.get('host')}${req.originalUrl}`);
    }
    next();
  });
}

const allowedKeys = new Set(
  API_KEYS.split(',').map(s => s.trim()).filter(Boolean)
);

function extractApiKey(req) {
  const k = req.get('x-api-key');
  if (k) return k.trim();
  const auth = req.get('authorization');
  if (auth && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  return null;
}

function timingSafeMatch(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function requireApiKey(req, res, next) {
  const provided = extractApiKey(req);
  if (!provided) return res.status(401).json({ error: 'Missing API key' });
  for (const k of allowedKeys) {
    if (timingSafeMatch(provided, k)) {
      req.apiKey = provided;
      return next();
    }
  }
  return res.status(403).json({ error: 'Invalid API key' });
}

const limiter = rateLimit({
  windowMs: parseInt(RATE_WINDOW_MS, 10),
  max: parseInt(RATE_MAX, 10),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractApiKey(req) || req.ip,
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

const MODES = {
  'aes-256-gcm': { code: 1, ivLen: 12, tagLen: 16, aead: true },
  'aes-256-cbc': { code: 2, ivLen: 16, tagLen: 0, aead: false },
  'aes-256-ctr': { code: 3, ivLen: 16, tagLen: 0, aead: false }
};
const CODE_TO_MODE = Object.fromEntries(
  Object.entries(MODES).map(([name, meta]) => [meta.code, { name, ...meta }])
);
const MAGIC1 = Buffer.from('AES1', 'ascii'); // legacy
const MAGIC2 = Buffer.from('AES2', 'ascii'); // streaming friendly

function validateMode(modeRaw) {
  const mode = String(modeRaw || '').toLowerCase();
  if (!MODES[mode]) throw new Error(`Unsupported mode. Use one of: ${Object.keys(MODES).join(', ')}`);
  return mode;
}

function deriveKey({ passphrase, salt }) {
  if (!passphrase || typeof passphrase !== 'string' || passphrase.length < 12) {
    throw new Error('Passphrase must be at least 12 characters');
  }
  return crypto.scryptSync(
    passphrase,
    salt,
    32,
    { N: 1 << 15, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }
  );
}

function parseKeyB64(key_b64) {
  let raw;
  try {
    raw = Buffer.from(key_b64, 'base64');
  } catch {
    throw new Error('Invalid key_b64 (Base64 decode failed)');
  }
  if (![16, 24, 32].includes(raw.length)) {
    throw new Error('key_b64 must decode to 16, 24, or 32 bytes');
  }

  if (raw.length !== 32) {
    raw = crypto.hkdfSync('sha256', raw, Buffer.alloc(0), Buffer.from('aes-256-upscale'), 32);
  }
  return raw;
}

function clampMaxSize(req, res, next) {
  const maxBytes = parseInt(MAX_FILE_MB, 10) * 1024 * 1024;
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);
  if (contentLength && contentLength > maxBytes) {
    return res.status(413).json({ error: `Payload too large (max ${MAX_FILE_MB} MB)` });
  }
  next();
}

function parseMultipart(req, { requireFile = true } = {}) {
  return new Promise((resolve, reject) => {
    if (!req.headers['content-type'] || !req.headers['content-type'].includes('multipart/form-data')) {
      return reject(new Error('Content-Type must be multipart/form-data'));
    }
    const bb = Busboy({ headers: req.headers, limits: { files: 1, fileSize: parseInt(MAX_FILE_MB, 10) * 1024 * 1024 } });
    const fields = {};
    let fileStream = null;
    let fileInfo = null;
    let fileFieldName = null;
    let fileTooLarge = false;

    bb.on('file', (name, stream, info) => {
      if (fileStream) {
        stream.resume();
        return;
      }
      fileFieldName = name;
      fileStream = stream;
      fileInfo = info;
      stream.on('limit', () => { fileTooLarge = true; });
    });

    bb.on('field', (name, val) => {
      fields[name] = val;
    });

    bb.on('error', (err) => reject(err));
    bb.on('finish', () => {
      if (fileTooLarge) return reject(new Error(`File too large (max ${MAX_FILE_MB} MB)`));
      if (requireFile && (!fileStream || !fileInfo)) return reject(new Error('Missing file'));
      resolve({ fields, fileStream, fileInfo, fileFieldName });
    });

    req.pipe(bb);
  });
}

function ensureSingleSecret({ passphrase, key_b64 }) {
  if (!!passphrase === !!key_b64) {
    throw new Error('Provide either passphrase OR key_b64 (exclusively)');
  }
}

function professional405(res) {
  res.status(405).type('html').send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Endpoint Not Supported</title>
      <style>
        :root { color-scheme: light dark; }
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background: #f6f7f9; }
        .wrap { max-width: 720px; margin: 6vh auto; padding: 0 20px; }
        .card { background: #fff; border-radius: 12px; padding: 28px; box-shadow: 0 10px 30px rgba(0,0,0,0.06); }
        h1 { margin: 0 0 8px; font-size: 1.6rem; color: #cc3344; }
        p { margin: 10px 0; color: #333; line-height: 1.55; }
        code { background: #eef0f3; padding: 2px 6px; border-radius: 6px; }
        @media (prefers-color-scheme: dark) {
          body { background: #0b0c0f; }
          .card { background: #14161a; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }
          h1 { color: #ff6b6b; }
          p, code { color: #d6d8dc; }
          code { background: #1f2329; }
        }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="card">
          <h1>405 – Method Not Allowed</h1>
          <p>This service accepts <code>POST</code> at <code>/encrypt</code> and <code>/decrypt</code> with <code>multipart/form-data</code>.</p>
          <p>Include your API key in <code>x-api-key</code> or <code>Authorization: Bearer &lt;key&gt;</code>.</p>
        </div>
      </div>
    </body>
    </html>
  `);
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/encrypt', clampMaxSize, requireApiKey, async (req, res) => {
  try {
    const { fields, fileStream, fileInfo } = await parseMultipart(req);
    const mode = validateMode(fields.mode);
    ensureSingleSecret({ passphrase: fields.passphrase, key_b64: fields.key_b64 });

    const modeMeta = MODES[mode];
    const iv = crypto.randomBytes(modeMeta.ivLen);
    const salt = crypto.randomBytes(16);
    const key = fields.key_b64 ? parseKeyB64(fields.key_b64) : deriveKey({ passphrase: fields.passphrase, salt });

    const cipher = crypto.createCipheriv(
      mode,
      key,
      iv,
      modeMeta.aead ? { authTagLength: modeMeta.tagLen } : undefined
    );

    if (modeMeta.aead && fields.aad_b64) {
      const aad = Buffer.from(fields.aad_b64, 'base64');
      cipher.setAAD(aad);
    }

    const outName = (fileInfo?.filename || 'file') + '.enc';
    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${outName.replace(/"/g, '')}"`,
      'X-Mode': mode
    });

    const header = Buffer.alloc(8);
    MAGIC2.copy(header, 0);
    header.writeUInt8(modeMeta.code, 4);
    header.writeUInt8(iv.length, 5);
    header.writeUInt8(salt.length, 6);
    header.writeUInt8(modeMeta.aead ? modeMeta.tagLen : 0, 7);
    res.write(header);
    res.write(iv);
    res.write(salt);

    fileStream.on('error', (e) => {
      res.destroy(e);
    });
    cipher.on('error', (e) => {
      res.destroy(e);
    });

    fileStream.on('data', (chunk) => {
      const out = cipher.update(chunk);
      if (out.length) res.write(out);
    });
    fileStream.on('end', () => {
      try {
        const final = cipher.final();
        if (final.length) res.write(final);
        if (modeMeta.aead) {
          const tag = cipher.getAuthTag();
          res.write(tag);
        }
        res.end();
      } catch (e) {
        res.status(400).json({ error: e.message || 'Encryption failed' });
      }
    });
  } catch (err) {
    if (!res.headersSent) res.status(400).json({ error: err.message || 'Encryption failed' });
    else res.end();
  }
});

app.post('/decrypt', clampMaxSize, requireApiKey, async (req, res) => {
  try {
    const { fields, fileStream, fileInfo } = await parseMultipart(req);
    function readN(stream, n) {
      return new Promise((resolve, reject) => {
        let bufs = [];
        let total = 0;
        function onData(chunk) {
          bufs.push(chunk);
          total += chunk.length;
          if (total >= n) {
            stream.pause();
            stream.removeListener('data', onData);
            stream.removeListener('end', onEnd);
            stream.removeListener('error', onErr);
            const all = Buffer.concat(bufs, total);
            const head = all.subarray(0, n);
            const rest = all.subarray(n);
            process.nextTick(() => {
              if (rest.length) stream.emit('data', rest);
              stream.resume();
            });
            resolve(head);
          }
        }
        function onEnd() { reject(new Error('Unexpected EOF')); }
        function onErr(e) { reject(e); }
        stream.on('data', onData);
        stream.on('end', onEnd);
        stream.on('error', onErr);
      });
    }

    const header = await readN(fileStream, 8);
    const magic = header.subarray(0, 4);
    const code = header.readUInt8(4);
    const ivLen = header.readUInt8(5);
    const saltLen = header.readUInt8(6);
    const tagLen = header.readUInt8(7);

    const modeMeta = CODE_TO_MODE[code];
    if (!modeMeta) throw new Error('Unsupported mode code in file');

    const iv = await readN(fileStream, ivLen);
    const salt = await readN(fileStream, saltLen);

    ensureSingleSecret({ passphrase: fields.passphrase, key_b64: fields.key_b64 });
    const key = fields.key_b64 ? parseKeyB64(fields.key_b64) : deriveKey({ passphrase: fields.passphrase, salt });

    const decipher = crypto.createDecipheriv(modeMeta.name, key, iv);

    if (modeMeta.aead) {
      if (tagLen !== modeMeta.tagLen) throw new Error('Invalid auth tag length');
      if (fields.aad_b64) {
        const aad = Buffer.from(fields.aad_b64, 'base64');
        decipher.setAAD(aad);
      }
    }

    const inName = fileInfo?.filename || 'file.enc';
    const outName = inName.endsWith('.enc') ? inName.slice(0, -4) : 'decrypted.bin';
    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${outName.replace(/"/g, '')}"`
    });

    if (magic.equals(MAGIC1)) {
      if (modeMeta.aead) {
        const tag = await readN(fileStream, tagLen);
        decipher.setAuthTag(tag);
        const tmpPath = path.join(os.tmpdir(), `dec-${Date.now()}-${crypto.randomBytes(6).toString('hex')}.bin`);
        const tmp = fs.createWriteStream(tmpPath);
        await new Promise((resolve, reject) => {
          fileStream.on('data', (chunk) => {
            try {
              const out = decipher.update(chunk);
              if (out.length) tmp.write(out);
            } catch (e) { reject(e); }
          });
          fileStream.on('end', () => {
            try {
              const final = decipher.final();
              if (final.length) tmp.write(final);
              tmp.end(); resolve();
            } catch (e) { reject(e); }
          });
          fileStream.on('error', reject);
          tmp.on('error', reject);
        });
        await new Promise((resolve, reject) => {
          const rs = fs.createReadStream(tmpPath);
          rs.on('error', reject);
          rs.on('end', () => resolve());
          rs.pipe(res);
        }).finally(() => {
          fs.unlink(tmpPath, () => {});
        });
      } else {
        fileStream.on('error', (e) => res.destroy(e));
        fileStream.on('data', (chunk) => {
          const out = decipher.update(chunk);
          if (out.length) res.write(out);
        });
        fileStream.on('end', () => {
          try {
            const final = decipher.final();
            if (final.length) res.write(final);
            res.end();
          } catch (e) {
            res.status(400).json({ error: e.message || 'Decryption failed' });
          }
        });
      }
    } else if (magic.equals(MAGIC2)) {
      if (modeMeta.aead) {
        const tmpPath = path.join(os.tmpdir(), `dec-${Date.now()}-${crypto.randomBytes(6).toString('hex')}.bin`);
        const tmp = fs.createWriteStream(tmpPath);
        let tail = Buffer.alloc(0);
        await new Promise((resolve, reject) => {
          fileStream.on('data', (chunk) => {
            try {
              const combined = Buffer.concat([tail, chunk]);
              if (combined.length > tagLen) {
                const passLen = combined.length - tagLen;
                const toPass = combined.subarray(0, passLen);
                tail = combined.subarray(passLen);
                const out = decipher.update(toPass);
                if (out.length) tmp.write(out);
              } else {
                tail = combined;
              }
            } catch (e) { reject(e); }
          });
          fileStream.on('end', () => {
            try {
              if (tail.length !== tagLen) return reject(new Error('Invalid file: missing auth tag'));
              decipher.setAuthTag(tail);
              const final = decipher.final();
              if (final.length) tmp.write(final);
              tmp.end(); resolve();
            } catch (e) { reject(e); }
          });
          fileStream.on('error', reject);
          tmp.on('error', reject);
        });
        await new Promise((resolve, reject) => {
          const rs = fs.createReadStream(tmpPath);
          rs.on('error', reject);
          rs.on('end', () => resolve());
          rs.pipe(res);
        }).finally(() => {
          fs.unlink(tmpPath, () => {});
        });
      } else {
        fileStream.on('error', (e) => res.destroy(e));
        fileStream.on('data', (chunk) => {
          const out = decipher.update(chunk);
          if (out.length) res.write(out);
        });
        fileStream.on('end', () => {
          try {
            const final = decipher.final();
            if (final.length) res.write(final);
            res.end();
          } catch (e) {
            res.status(400).json({ error: e.message || 'Decryption failed' });
          }
        });
      }
    } else {
      throw new Error('Invalid file: magic mismatch');
    }
  } catch (err) {
    if (!res.headersSent) res.status(400).json({ error: err.message || 'Decryption failed' });
    else res.end();
  }
});

app.options(['/encrypt', '/decrypt'], (req, res) => {
  res.set('Allow', 'POST, OPTIONS').status(204).end();
});

app.all(['/encrypt', '/decrypt'], (req, res) => {
  res.set('Allow', 'POST, OPTIONS');
  res.status(405).json({ error: 'Method Not Allowed. Use POST with multipart/form-data.' });
});

app.get('*', (req, res) => {
  professional405(res);
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (!res.headersSent) res.status(500).json({ error: 'Internal Server Error' });
  else res.end();
});

app.listen(parseInt(PORT, 10), () => {
  console.log(`Server listening on port ${PORT}`);
  if (!allowedKeys.size) {
    console.warn('WARNING: No API keys configured. Set API_KEYS env (comma-separated).');
  }
});
