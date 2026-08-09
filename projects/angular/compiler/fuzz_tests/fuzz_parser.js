// Copyright 2023 Google LLC
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

const { FuzzedDataProvider } = require('@jazzer.js/core');
const { Lexer } = require('../src/expression_parser/lexer');
const { Parser } = require('../src/expression_parser/parser');

function createParser() {
    return new Parser(new Lexer())
}
function parseAction(text, location = null, offset = 0) {
    return createParser().parseAction(text, /* isAssignmentEvent */ false, location, offset);
}

function parseBinding(text, location = null, offset = 0) {
    return createParser().parseBinding(text, location, offset);
}

function parseInterpolation(text, location = null, offset = 0) {
    return createParser().parseInterpolation(text, location, offset, null);
}

function splitInterpolation(text, location = null) {
    return createParser().splitInterpolation(text, location, null);
}

function parseSimpleBinding(text, location = null, offset = 0) {
    return createParser().parseSimpleBinding(text, location, offset);
}

const parsingTasks = [
    parseAction,
    parseBinding,
    parseInterpolation,
    parseSimpleBinding,
    splitInterpolation
]

module.exports.fuzz = function(data) {
    const provider = new FuzzedDataProvider(data);

    const action = provider.consumeIntegralInRange(0, parsingTasks.length);
    const text = provider.consumeRemainingAsString();
    try {
        parsingTasks[action](text);
    } catch (error) {
    }
};
