import { mbkautheVar } from "#config.js";

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  '0.0.0.0',
  'metadata.google.internal',
  'metadata',
]);

function isPrivateIpv4(hostname) {
  const parts = hostname.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }

  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateIpv6(hostname) {
  const normalized = hostname.toLowerCase();
  if (normalized === '::1' || normalized === '::') return true;
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  if (normalized.startsWith('fe80:')) return true;
  return false;
}

function isBlockedHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  if (BLOCKED_HOSTNAMES.has(normalized)) return true;
  if (normalized.endsWith('.localhost') || normalized.endsWith('.local')) return true;
  if (normalized.includes(':') && isPrivateIpv6(normalized)) return true;
  if (isPrivateIpv4(normalized)) return true;
  return false;
}

/**
 * Returns true when a URL is safe for server-side fetch (profile images, etc.).
 */
export function isSafeFetchUrl(urlString) {
  if (!urlString || typeof urlString !== 'string' || urlString === 'default') {
    return false;
  }

  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return false;
  }

  const allowHttpInDev = mbkautheVar.IS_DEPLOYED !== 'true';
  const allowedProtocols = allowHttpInDev ? ['https:', 'http:'] : ['https:'];
  if (!allowedProtocols.includes(parsed.protocol)) return false;
  if (parsed.username || parsed.password) return false;
  if (!parsed.hostname) return false;
  if (isBlockedHostname(parsed.hostname)) return false;

  return true;
}
