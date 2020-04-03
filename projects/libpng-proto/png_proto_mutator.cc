/*
 * Copyright 2020 Google Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "png_fuzz_proto.pb.h"

template <typename Proto>
using FuzzMutatorCallback = std::function<void(Proto*, unsigned int)>;

template <typename Proto>
struct PngProtoCBRegistration
{
	PngProtoCBRegistration(FuzzMutatorCallback<Proto> const& _callback)
	{
		static protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto> reg = {_callback};
	}
};

/// Custom mutation: Otherchunk unknown_type -> known_type
static PngProtoCBRegistration<OtherChunk> addCustomChunk = {
	[](OtherChunk* message, unsigned int seed)
	{
		// Mutate with a probability of roughly 1/47
		// 47 has been chosen ad-hoc
		if (seed % 47 == 0)
		{
			// If otherChunk is unknown type, mutate
			// it to known type
			if (message->has_unknown_type())
			{
				// This is our custom mutation
				// We assume (k * 47 mod N) distribute
				// uniformly, where
				//  - N is total number of known
				// chunks defined by png proto converter
				//  - k is a factor of seed
				message->set_known_type(seed);
			}
		}
	}
};
