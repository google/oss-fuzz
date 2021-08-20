fuzz/parse_store_path: fuzz/target_parse_store_path.cc src/libstore/libnixstore.a src/libutil/libnixutil.a
	$(CXX) -v $(CPPFLAGS) $(GLOBAL_CXXFLAGS_PCH) $(GLOBAL_CXXFLAGS) $(LIB_FUZZING_ENGINE) $(nix_CXXFLAGS) -static $^ $(libstore_LDFLAGS_USE) $(libutil_LDFLAGS_USE) -o $@
