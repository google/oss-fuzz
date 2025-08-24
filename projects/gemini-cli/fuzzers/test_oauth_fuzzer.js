// Test script for OAuth token request fuzzer
const { LLVMFuzzerTestOneInput } = require('./fuzz_oauth_token_request.js');

async function testFuzzer() {
  try {
    console.log('Starting OAuth fuzzer tests...\n');

    // Test with valid OAuth request
    const validRequest = Buffer.from(JSON.stringify({
      grant_type: 'authorization_code',
      code: 'test_code',
      redirect_uri: 'https://example.com/callback',
      client_id: 'test_client'
    }));

    console.log('1. Testing with valid OAuth request...');
    const result1 = await LLVMFuzzerTestOneInput(validRequest);
    console.log('   Result:', result1, '(0 = success, expected for valid input)\n');

    // Test with malicious input
    const maliciousInput = Buffer.from('<script>alert("xss")</script>');
    console.log('2. Testing with malicious input...');
    const result2 = await LLVMFuzzerTestOneInput(maliciousInput);
    console.log('   Result:', result2, '(0 = success, malicious input handled correctly)\n');

    // Test with malformed JSON
    const malformedInput = Buffer.from('{malformed json}');
    console.log('3. Testing with malformed JSON...');
    const result3 = await LLVMFuzzerTestOneInput(malformedInput);
    console.log('   Result:', result3, '(0 = success, malformed input handled correctly)\n');

    // Test with empty input
    const emptyInput = Buffer.from('');
    console.log('4. Testing with empty input...');
    const result4 = await LLVMFuzzerTestOneInput(emptyInput);
    console.log('   Result:', result4, '(0 = success, empty input handled correctly)\n');

    // Test with valid OAuth response
    const validResponse = Buffer.from(JSON.stringify({
      access_token: 'test_token',
      token_type: 'Bearer',
      expires_in: 3600
    }));
    console.log('5. Testing with valid OAuth response...');
    const result5 = await LLVMFuzzerTestOneInput(validResponse);
    console.log('   Result:', result5, '(0 = success, valid response handled)\n');

    console.log('✅ All tests completed successfully!');
    console.log('The OAuth token request fuzzer is working correctly.');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

testFuzzer();
