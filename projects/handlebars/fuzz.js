// Fuzz harness for Handlebars — template engine (21 GHSA advisories)
const Handlebars = require("handlebars");
module.exports.fuzz = function (data) {
  try { Handlebars.compile(data.toString()); } catch (e) {}
};
