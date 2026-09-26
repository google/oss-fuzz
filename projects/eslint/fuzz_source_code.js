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

// Drives SourceCode-side APIs through the linter. Linter.verify() parses the
// source and stashes the resulting SourceCode on the linter; we then exercise
// the read-only inspection helpers that rules call into. Bugs in token/comment
// indexing or location lookups tend to surface here rather than in verify().
module.exports.fuzz = function (data) {
	const provider = new FuzzedDataProvider(data);

	const ecmaVersion = provider.consumeIntegralInRange(2015, 2024);
	const sourceType = provider.consumeBoolean() ? "module" : "script";

	const config = {
		languageOptions: {
			ecmaVersion,
			sourceType,
		},
	};

	const code = provider.consumeRemainingAsString();

	try {
		linter.verify(code, config);
	} catch (e) {
		if (isExpectedConfigurationError(e)) {
			return;
		}
		throw e;
	}

	const sourceCode = linter.getSourceCode();
	if (!sourceCode || !sourceCode.ast) {
		// Parsing failed - the parser error is surfaced as a lint message and
		// no SourceCode is produced. Nothing more to fuzz on this input.
		return;
	}

	try {
		// Token APIs.
		const tokens = sourceCode.ast.tokens || [];
		if (tokens.length > 0) {
			const t = tokens[0];
			sourceCode.getTokenByRangeStart(t.range[0]);
			sourceCode.getTokenBefore(t);
			sourceCode.getTokenAfter(t);
			sourceCode.getFirstToken(sourceCode.ast);
			sourceCode.getLastToken(sourceCode.ast);
		}

		// Comment APIs.
		sourceCode.getAllComments();

		// Text/location APIs.
		sourceCode.getText();
		sourceCode.getLines();
		const totalLength = sourceCode.getText().length;
		if (totalLength > 0) {
			const offset = provider.consumeIntegralInRange(0, totalLength - 1);
			sourceCode.getLocFromIndex(offset);
		}

		// Scope and ancestor APIs (driven through the AST root).
		sourceCode.getScope(sourceCode.ast);
		sourceCode.getAncestors(sourceCode.ast);
	} catch (e) {
		// The above are documented public APIs and should not throw on any
		// successfully-parsed input - re-raise so the fuzzer reports it.
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
		msg.includes("ecmaVersion must be") ||
		msg.includes("sourceType must be")
	);
}
