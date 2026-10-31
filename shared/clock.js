/**
 * shared/clock.js
 * Modul jam yang dapat di-override untuk testing.
 * Memungkinkan pengujian kondisi di luar jam akses tanpa menunggu waktu nyata.
 */

let _overrideHour = null;

/**
 * Mendapatkan jam saat ini dalam timezone yang dikonfigurasi.
 * @param {string} timezone - Timezone, default 'Asia/Jakarta'
 * @returns {number} Jam (0-23)
 */
function getCurrentHour(timezone) {
  if (_overrideHour !== null) {
    return _overrideHour;
  }
  const tz = timezone || 'Asia/Jakarta';
  const now = new Date();
  const formatter = new Intl.DateTimeFormat('en-US', {
    hour: 'numeric',
    hour12: false,
    timeZone: tz,
  });
  return parseInt(formatter.format(now), 10);
}

/**
 * Memeriksa apakah saat ini dalam jam akses yang diizinkan.
 * Jam akhir bersifat eksklusif: akses diizinkan pada [startHour, endHour).
 * Contoh: 7-21 berarti 07:00 sampai 20:59.
 * @param {number} startHour
 * @param {number} endHour
 * @param {string} timezone
 * @returns {boolean}
 */
function isWithinAccessHours(startHour, endHour, timezone) {
  const currentHour = getCurrentHour(timezone);
  return currentHour >= startHour && currentHour < endHour;
}

/**
 * Override jam untuk testing. Set null untuk kembali ke waktu nyata.
 * @param {number|null} hour
 */
function setOverrideHour(hour) {
  _overrideHour = hour;
}

/**
 * Mendapatkan nilai override saat ini (untuk debugging).
 * @returns {number|null}
 */
function getOverrideHour() {
  return _overrideHour;
}

module.exports = { getCurrentHour, isWithinAccessHours, setOverrideHour, getOverrideHour };
