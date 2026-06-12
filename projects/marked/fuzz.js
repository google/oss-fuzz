// Fuzz harness for marked — markdown parser (18 GHSA advisories)
const marked = require("marked");
module.exports.fuzz = function (data) {
  try { marked.parse(data.toString()); } catch (e) {}
};
