/**
 * Geolocation helpers for anomaly detection.
 */

const R_KM = 6371; // earth radius in km

function toRad(value) {
  return (value * Math.PI) / 180;
}

/**
 * Haversine distance between two lat/lon points in kilometres.
 * Returns null when either coordinate is missing/invalid.
 */
function haversineDistance(lat1, lon1, lat2, lon2) {
  if ([lat1, lon1, lat2, lon2].some((n) => n === null || n === undefined || Number.isNaN(Number(n)))) {
    return null;
  }

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round((R_KM * c) * 10) / 10; // km, 1 decimal
}

/**
 * Approximate the maximum physically-plausible travel speed (km/h).
 * 3000 km/h comfortably covers commercial flight + ground transfer with margin.
 */
const MAX_PLAUSIBLE_SPEED_KMH = 3000;

/**
 * Assess whether a login attempt represents impossible travel between the
 * previous successful location and the current one.
 *
 * @param {object} params
 * @param {{country?:string,city?:string,latitude?:number,longitude?:number,ts?:number}} from  previous successful login
 * @param {{country?:string,city?:string,latitude?:number,longitude?:number,ts?:number}} to    current attempt
 * @returns {{impossible:boolean,distanceKm:number|null,speedKmh:number|null,reason:string|null}}
 */
function assessImpossibleTravel(from, to) {
  const base = { impossible: false, distanceKm: null, speedKmh: null, reason: null };

  if (!from || !to) return base;
  if (!from.latitude || !from.longitude || !to.latitude || !to.longitude) return base;
  if (from.ts == null || to.ts == null) return base;

  const distanceKm = haversineDistance(from.latitude, from.longitude, to.latitude, to.longitude);
  const elapsedHours = (to.ts - from.ts) / (1000 * 3600);

  if (distanceKm === 0) return base; // same location
  if (elapsedHours <= 0) {
    // Logged in within the same instant from a different place — impossible.
    return {
      impossible: true,
      distanceKm,
      speedKmh: null,
      reason: `Login from ${to.city || to.country || 'unknown'} within seconds of a previous login ${distanceKm} km away from ${from.city || from.country || 'unknown'}`,
    };
  }

  const speedKmh = distanceKm / elapsedHours;
  if (speedKmh > MAX_PLAUSIBLE_SPEED_KMH) {
    return {
      impossible: true,
      distanceKm,
      speedKmh: Math.round(speedKmh),
      reason: `Impossible travel: ${distanceKm} km in ${elapsedHours.toFixed(2)}h (${Math.round(speedKmh)} km/h)`,
    };
  }

  return base;
}

module.exports = { haversineDistance, assessImpossibleTravel, MAX_PLAUSIBLE_SPEED_KMH };
