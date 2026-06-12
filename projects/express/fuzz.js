// Fuzz harness for express — Node.js framework (6 GHSA advisories)
const express = require("express");

module.exports.fuzz = function (data) {
  try {
    const path = data.toString();
    const app = express();
    app.get(path, (req, res) => { res.send("ok"); });
  } catch (e) {}
};
