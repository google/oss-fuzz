// Fuzz harness for axios — HTTP client (30 GHSA advisories)
const axios = require("axios");

module.exports.fuzz = function (data) {
  try {
    // URL parsing
    const url = data.toString();
    if (url.length > 0) {
      axios.get(url).catch(() => {});
    }
  } catch (e) {}
};
