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

const ECMA_VERSIONS = [3, 5, 2015, 2018, 2020, 2022, 2024, "latest"];
const SOURCE_TYPES = ["script", "module", "commonjs"];

// A representative cross-section of rules. This mixes parser-touching rules,
// scope-analysis rules, AST-shape rules, and rules with non-trivial state
// (control-flow graph, autofix, suggestions) so the fuzzer exercises many
// different parts of the linter from a single entry point.
const RULE_POOL = [
	"no-cond-assign",
	"no-constant-condition",
	"no-dupe-args",
	"no-dupe-keys",
	"no-empty",
	"no-extra-boolean-cast",
	"no-irregular-whitespace",
	"no-redeclare",
	"no-undef",
	"no-unreachable",
	"no-unused-vars",
	"no-use-before-define",
	"complexity",
	"max-depth",
	"max-nested-callbacks",
	"max-params",
	"prefer-const",
	"semi",
	"quotes",
	"eqeqeq",
	"curly",
	"no-var",
	"no-multi-spaces",
	"no-trailing-spaces",
];

/**
 * Pick a small random subset of rules to enable. Enabling all rules at once
 * obscures coverage signal because the cheap rules dominate; instead we let
 * the fuzzer drive which rules are co-enabled.
 *
 * @param {FuzzedDataProvider} provider
 * @returns {Object}
 */
function pickRules(provider) {
	const rules = {};
	const count = provider.consumeIntegralInRange(0, 8);
	for (let i = 0; i < count; i++) {
		const idx = provider.consumeIntegralInRange(0, RULE_POOL.length - 1);
		rules[RULE_POOL[idx]] = "error";
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
	const allowInlineConfig = provider.consumeBoolean();
	const reportUnusedDisableDirectives = provider.consumeBoolean();

	const config = {
		languageOptions: {
			ecmaVersion,
			sourceType,
			parserOptions: {
				ecmaFeatures: {
					jsx: provider.consumeBoolean(),
					globalReturn: provider.consumeBoolean(),
				},
			},
		},
		linterOptions: {
			reportUnusedDisableDirectives,
		},
		rules: pickRules(provider),
	};

	const code = provider.consumeRemainingAsString();

	try {
		linter.verify(code, config, { allowInlineConfig });
	} catch (e) {
		// ESLint surfaces parser errors as lint messages, so any thrown error
		// is unexpected. A handful of errors are caused by the fuzzer-generated
		// configuration rather than the source code under test - filter those
		// out so they don't drown out real bugs.
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
		msg.includes("Key \"linterOptions\":") ||
		msg.includes("Key \"rules\":") ||
		msg.includes("ecmaVersion must be") ||
		msg.includes("sourceType must be")
	);
}
