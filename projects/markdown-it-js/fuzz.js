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
