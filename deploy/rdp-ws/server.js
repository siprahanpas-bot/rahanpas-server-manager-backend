const crypto = require('crypto');
const GuacamoleLite = require('guacamole-lite');

const secret = process.env.RDP_BRIDGE_SECRET || '';

if (secret.length < 32) {
  throw new Error('RDP_BRIDGE_SECRET wajib diisi dan minimal 32 karakter.');
}

const port = Number(process.env.RDP_BRIDGE_PORT || 8080);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('RDP_BRIDGE_PORT tidak valid.');
}

const key32 = crypto.createHash('sha256').update(secret).digest();

const guacdOptions = {
  host: process.env.GUACD_HOST || 'rahanpas-guacd',
  port: Number(process.env.GUACD_PORT || 4822),
};

const clientOptions = {
  crypt: {
    cypher: 'AES-256-CBC',
    key: key32,
  },
};

new GuacamoleLite({ port }, guacdOptions, clientOptions);
console.log(`Rahanpas RDP WebSocket bridge listening on :${port}`);
