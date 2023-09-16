const { FuzzedDataProvider } = require('@jazzer.js/core');
const markdownIt = require('markdown-it');
const md = markdownIt();

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const markdownContent = provider.consumeString(provider.consumeIntegralInRange(1, 4096));

    // Render the markdown content
    const htmlOutput = md.render(markdownContent);

    // Optionally, you can test other functionalities of markdown-it
    // For example, you can test the inline rendering:
    const inlineOutput = md.renderInline(markdownContent);

    // If markdown-it had more functionalities like plugins, options, etc., 
    // you would include them here in a similar manner, using the FuzzedDataProvider 
    // to generate random inputs for those functionalities.

  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  // List of error messages that you want the fuzzer to ignore.
  // For example, if markdown-it throws specific errors for invalid inputs 
  // that you're not interested in, you can list them here.
  const ignored = [
    // "Example error message to ignore",
  ];
  return Boolean(ignored.find((message) => error.message.indexOf(message) !== -1));
}
