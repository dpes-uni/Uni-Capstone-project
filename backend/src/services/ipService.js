const NodeCache = require('node-cache');
const axios = require('axios');
const logger = require('../utils/logger');

// Cache IP geolocation results for 1 hour (3600 seconds)
const ipCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

/**
 * Get geolocation data for an IP address.
 * Uses ipapi.co free API with caching.
 * @param {string} ip - IP address
 * @returns {Promise<{country: string, city: string, latitude: number|null, longitude: number|null, org: string, asn: (number|null)}>}
 */
async function getIpGeolocation(ip) {
  // Return cached data if available
  const cached = ipCache.get(ip);
  if (cached) {
    return cached;
  }

  // Default values if lookup fails
  const defaultData = { country: 'Unknown', city: 'Unknown', latitude: null, longitude: null, org: '', asn: null };

  // Skip lookup for reserved/IPs
  if (!ip || ip === 'unknown' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.') || ip.startsWith('127.')) {
    ipCache.set(ip, defaultData);
    return defaultData;
  }

  try {
    const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 5000, // 5 seconds timeout
    });

    const data = {
      country: response.data.country_name || 'Unknown',
      city: response.data.city || 'Unknown',
      latitude: response.data.latitude || null,
      longitude: response.data.longitude || null,
      org: response.data.org || '',
      asn: response.data.asn || null,
    };

    // Cache the result
    ipCache.set(ip, data);
    return data;
  } catch (error) {
    logger.warn(`IP geolocation lookup failed for ${ip}`, { error: error.message });
    // Cache default to avoid repeated failed lookups
    ipCache.set(ip, defaultData);
    return defaultData;
  }
}

// Keywords / brand names that strongly indicate a VPN, proxy, or anonymising
// network. This is a best-effort heuristic: without a commercial VPN/IP feed
// we cannot be certain, but these patterns catch the common cases.
const VPN_SIGNALS = [
  'vpn',
  'proxy',
  'tor',
  'the onion router',
  'datacenter',
  'data center',
  'hosting',
  'nordvpn',
  'expressvpn',
  'mullvad',
  'protonvpn',
  'surfshark',
  'cyberghost',
  'torguard',
  'ipvanish',
  'private internet access',
  'purevpn',
  'vyprvpn',
  'ovpn',
  'm247',
  'datacamp',
];

/**
 * Best-effort VPN / proxy / anonymiser detection from IP geolocation metadata.
 * Returns true when the owning organisation (org/ASN) matches known
 * anonymising infrastructure. Deliberately excludes generic cloud providers
 * (AWS, GCP, Azure, etc.) to avoid false positives from legitimate corporate
 * networks.
 * @param {{org?: string, asn?: number|null}} geo
 * @returns {boolean}
 */
function detectVpn(geo = {}) {
  const org = String(geo.org || '').toLowerCase();
  if (!org) {
    return false;
  }
  return VPN_SIGNALS.some((signal) => org.includes(signal));
}

module.exports = { getIpGeolocation, detectVpn };