// Release-code authentication using a bcrypt master key.
// The MASTER_KEY_HASH is the bcrypt hash of the valid access code.
// Device binding is stored in Netlify Blobs to restrict access to one computer.

const bcrypt = require('bcryptjs');
const { getStore } = require('@netlify/blobs');

const MASTER_KEY_HASH = '$2a$10$VPXUZhHbiYa.fRJCcC4av.HkqcGjG0gFujvv3a1qI1Ys0GK6lcwGa';
const BINDING_KEY = 'master-device';

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON body' }) };
  }

  const { code, device } = body;

  if (!code || typeof code !== 'string') {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing release code' }) };
  }
  if (!device || typeof device !== 'string') {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing device identifier' }) };
  }

  // Verify the entered code against the stored bcrypt hash
  let isValid = false;
  try {
    isValid = await bcrypt.compare(code.trim(), MASTER_KEY_HASH);
  } catch (err) {
    console.error('bcrypt compare error:', err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Validation error' }) };
  }

  if (!isValid) {
    return { statusCode: 200, headers, body: JSON.stringify({ valid: false, reason: 'invalid_code' }) };
  }

  // Device binding: once validated, tie the access to one device fingerprint
  try {
    const store = getStore({ name: 'device-bindings', consistency: 'strong' });
    const binding = await store.get(BINDING_KEY, { type: 'json' });

    if (binding) {
      if (binding.device !== device) {
        return { statusCode: 200, headers, body: JSON.stringify({ valid: false, reason: 'device_mismatch' }) };
      }
    } else {
      // First successful validation — bind this device
      await store.setJSON(BINDING_KEY, { device, boundAt: new Date().toISOString() });
    }
  } catch (err) {
    console.error('Blobs error:', err);
    // If Blobs are unavailable, fall back to allowing access (binding is best-effort)
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ valid: true }),
  };
};
