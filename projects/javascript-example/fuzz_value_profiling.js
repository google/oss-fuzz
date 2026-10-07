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

/**
 * @param {number} n
 */
function encrypt(n) {
	return n ^ 0x11223344;
}

/**
 * @param { Buffer } data
 */
module.exports.fuzz = function (data) {
	if (data.length < 16) {
		return;
	}
	if (
		encrypt(data.readInt32BE(0)) === 0x50555637 &&
		encrypt(data.readInt32BE(4)) === 0x7e4f5664 &&
		encrypt(data.readInt32BE(8)) === 0x5757493e &&
		encrypt(data.readInt32BE(12)) === 0x784c5465
	) {
		throw Error("XOR with a constant is not a secure encryption method ;-)");
	}
};
