#!/bin/bash -eu
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzOpen fuzz_box_open
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzOpenPassphrase fuzz_box_open_passphrase
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzSealOpenRoundTrip fuzz_box_seal_open_round_trip
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzBitFlip fuzz_box_bit_flip
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/armor FuzzArmor fuzz_armor
compile_native_go_fuzzer github.com/ruddro-roy/sindook/xwing FuzzDecapsulate fuzz_xwing_decapsulate
