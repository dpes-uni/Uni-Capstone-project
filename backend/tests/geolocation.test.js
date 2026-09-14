const { haversineDistance, assessImpossibleTravel, MAX_PLAUSIBLE_SPEED_KMH } = require('../src/utils/geolocation');

describe('geolocation / impossible travel', () => {
  test('haversineDistance computes known distances', () => {
    // NYC -> LA ~ 3935 km
    const d = haversineDistance(40.7128, -74.006, 34.0522, -118.2437);
    expect(d).toBeGreaterThan(3900);
    expect(d).toBeLessThan(4100);
  });

  test('haversineDistance returns null on bad coords', () => {
    expect(haversineDistance(null, -1, 2, 3)).toBeNull();
    expect(haversineDistance(0, 0, undefined, 0)).toBeNull();
  });

  test('haversineDistance is zero for same point', () => {
    expect(haversineDistance(10, 10, 10, 10)).toBe(0);
  });

  test('detects same-instant travel from different places as impossible', () => {
    const result = assessImpossibleTravel(
      { latitude: 40.71, longitude: -74.0, city: 'New York', country: 'US', ts: 1000 },
      { latitude: 51.51, longitude: -0.13, city: 'London', country: 'GB', ts: 1000 }
    );
    expect(result.impossible).toBe(true);
    expect(result.distanceKm).toBeGreaterThan(5000);
    expect(result.reason).toMatch(/within seconds/);
  });

  test('flags travel exceeding max plausible speed', () => {
    const oneHour = 60 * 60 * 1000;
    const result = assessImpossibleTravel(
      { latitude: 40.71, longitude: -74.0, city: 'NYC', country: 'US', ts: 1000 },
      { latitude: 35.68, longitude: 139.69, city: 'Tokyo', country: 'JP', ts: 1000 + oneHour }
    );
    expect(result.impossible).toBe(true);
    expect(result.speedKmh).toBeGreaterThan(MAX_PLAUSIBLE_SPEED_KMH);
    expect(result.reason).toMatch(/Impossible travel/);
  });

  test('does not flag plausible travel', () => {
    // 8 hours NYC -> LA (~3930 km) = ~491 km/h, well under 3000 km/h
    const eightHours = 8 * 60 * 60 * 1000;
    const result = assessImpossibleTravel(
      { latitude: 40.71, longitude: -74.0, city: 'NYC', country: 'US', ts: 0 },
      { latitude: 34.05, longitude: -118.24, city: 'LA', country: 'US', ts: eightHours }
    );
    expect(result.impossible).toBe(false);
    expect(result.reason).toBeNull();
  });

  test('returns safe defaults when history is missing', () => {
    const now = Date.now();
    const result = assessImpossibleTravel(null, { latitude: 1, longitude: 2, city: 'X', ts: now });
    expect(result.impossible).toBe(false);
    expect(result.reason).toBeNull();
  });
});