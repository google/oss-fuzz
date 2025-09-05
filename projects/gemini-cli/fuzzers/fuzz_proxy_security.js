const { FuzzedDataProvider } = require('@jazzer.js/core');

function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) return 0;

  const fdp = new FuzzedDataProvider(data);
  const input = fdp.consumeString(data.length);

  try {
    // Simple proxy security validation
    if (input.includes('http://') || input.includes('https://')) {
      const url = new URL(input);
      // Basic validation that doesn't crash
      if (url.hostname) {
        // Success
      }
    }
  } catch (e) {
    // Expected URL parsing errors
  }

  return 0;
}

module.exports = { LLVMFuzzerTestOneInput };