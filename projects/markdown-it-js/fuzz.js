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

const MarkdownIt = require('markdown-it');

/**
 * @param { Buffer } data
 */
module.exports.fuzz = function (data) {
    const s = data.toString();
    try {
        // Using commonmark mode
        const mdCommonMark = new MarkdownIt('commonmark');
        mdCommonMark.render(s);

        // Using default mode
        const mdDefault = new MarkdownIt();
        mdDefault.render(s);

        // Enabling everything
        const mdEverythingEnabled = new MarkdownIt({
            html: true,
            linkify: true,
            typographer: true
        });
        mdEverythingEnabled.render(s);

        // Using full options list with defaults
        const mdFullOptions = new MarkdownIt({
            html: false,
            xhtmlOut: false,
            breaks: false,
            langPrefix: 'language-',
            linkify: false,
            typographer: false,
            quotes: '“”‘’',
            highlight: function (/*str, lang*/) { return ''; }
        });
        mdFullOptions.render(s);
    } catch (e) {
        throw e;
    }
};
