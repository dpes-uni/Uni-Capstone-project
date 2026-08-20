const NodeCache = require('node-cache');
const axios = require('axios');
const logger = require('../utils/logger');

// Cache IP geolocation results for 1 hour (3600 seconds)
const ipCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

/**
 * Get geolocation data for an IP address.
 * Uses ipapi.co free API with caching.
 * @param {string} ip - IP address
 * @returns {Promise<{country: string, city: string}>}
 */
async function getIpGeolocation(ip) {
  // Return cached data if available
  const cached = ipCache.get(ip);
  if (cached) {
    return cached;
  }

  // Default values if lookup fails
  const defaultData = { country: 'Unknown', city: 'Unknown' };

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

module.exports = { getIpGeolocation };