import { mbkautheVar } from "#config.js";

const BLOCKED_HOSTNAMES = new Set(['localhost', '0.0.0.0', 'metadata.google.internal', 'metadata']);

function isPrivateIpv4(hostname) {
  const parts = hostname.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return false;

  const [a, b] = parts;
  return a === 10 || a === 127 || a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127);
}

function isPrivateIpv6(hostname) {
  const norm = hostname.toLowerCase();
  return norm === '::1' || norm === '::' || norm.startsWith('fc') || norm.startsWith('fd') || norm.startsWith('fe80:');
}

function isBlockedHostname(hostname) {
  const norm = hostname.toLowerCase().replace(/\.$/, '');
  return BLOCKED_HOSTNAMES.has(norm) ||
    norm.endsWith('.localhost') ||
    norm.endsWith('.local') ||
    (norm.includes(':') && isPrivateIpv6(norm)) ||
    isPrivateIpv4(norm);
}

/**
 * Returns true when a URL is safe for server-side fetch (profile images, etc.).
 */
export function isSafeFetchUrl(urlString) {
  if (!urlString || typeof urlString !== 'string' || urlString === 'default') return false;

  try {
    const parsed = new URL(urlString);
    const allowedProtocols = mbkautheVar.IS_DEPLOYED === 'true' ? ['https:'] : ['https:', 'http:'];
    return (
      allowedProtocols.includes(parsed.protocol) &&
      !parsed.username &&
      !parsed.password &&
      Boolean(parsed.hostname) &&
      !isBlockedHostname(parsed.hostname)
    );
  } catch {
    return false;
  }
}
