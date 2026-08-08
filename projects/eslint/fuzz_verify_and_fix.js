// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

"use strict";

const { FuzzedDataProvider } = require("@jazzer.js/core");
const { Linter } = require("./lib/linter");

const linter = new Linter();

// Restrict to rules that ship with autofixers. The verifyAndFix path runs the
// fixer in a loop until convergence, so it stresses fixer composition and the
// "fixes that touch overlapping ranges" path that pure verify() misses.
const FIXABLE_RULE_POOL = [
	"semi",
	"quotes",
	"no-extra-semi",
	"no-extra-boolean-cast",
	"no-trailing-spaces",
	"no-multi-spaces",
	"prefer-const",
	"no-var",
	"eqeqeq",
	"curly",
	"dot-notation",
	"object-shorthand",
	"prefer-arrow-callback",
	"prefer-template",
	"arrow-parens",
	"arrow-spacing",
	"comma-dangle",
	"comma-spacing",
	"indent",
	"key-spacing",
	"keyword-spacing",
	"no-extra-parens",
	"no-useless-rename",
	"no-useless-return",
	"yoda",
];

const ECMA_VERSIONS = [5, 2015, 2018, 2020, 2022, 2024, "latest"];
const SOURCE_TYPES = ["script", "module", "commonjs"];

function pickRules(provider) {
	const rules = {};
	const count = provider.consumeIntegralInRange(1, 6);
	for (let i = 0; i < count; i++) {
		const idx = provider.consumeIntegralInRange(
			0,
			FIXABLE_RULE_POOL.length - 1,
		);
		rules[FIXABLE_RULE_POOL[idx]] = "error";
	}
	return rules;
}

/**
 * @param { Buffer } data
 */
module.exports.fuzz = function (data) {
	const provider = new FuzzedDataProvider(data);

	const ecmaVersion =
		ECMA_VERSIONS[provider.consumeIntegralInRange(0, ECMA_VERSIONS.length - 1)];
	const sourceType =
		SOURCE_TYPES[provider.consumeIntegralInRange(0, SOURCE_TYPES.length - 1)];
	const fix = provider.consumeBoolean();

	const config = {
		languageOptions: {
			ecmaVersion,
			sourceType,
		},
		rules: pickRules(provider),
	};

	const code = provider.consumeRemainingAsString();

	try {
		linter.verifyAndFix(code, config, { fix });
	} catch (e) {
		if (isExpectedConfigurationError(e)) {
			return;
		}
		throw e;
	}
};

function isExpectedConfigurationError(e) {
	if (!e || typeof e.message !== "string") {
		return false;
	}
	const msg = e.message;
	return (
		msg.includes("Key \"languageOptions\":") ||
		msg.includes("Key \"rules\":") ||
		msg.includes("ecmaVersion must be") ||
		msg.includes("sourceType must be")
	);
}
