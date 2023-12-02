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

const { FuzzedDataProvider } = require('@jazzer.js/core')
const crypto = require('crypto');
const buffer = require('buffer');

// a private key
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                                         modulusLength: 2048,
	});
// Hashing Algorithm
const algorithm = "SHA256";

module.exports.fuzz = async function(data) {
	const provider = new FuzzedDataProvider(data)

	// Create strings
	const dataString1 = provider.consumeString(provider.consumeIntegralInRange(1, 4096))
	const dataString2 = provider.consumeString(provider.consumeIntegralInRange(1, 4096))

	// Create buffers
	let buf1 = Buffer.from(dataString1);
	let buf2 = Buffer.from(dataString2);
 
	// Sign the data and returned signature in buffer
	let signature = crypto.sign(algorithm, buf1, privateKey);
 
	// Verifying signature using crypto.verify() function
	let isVerified = crypto.verify(algorithm, buf2, publicKey, signature);

}

