# frozen_string_literal: true
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
# Fuzzer for CarrierWave URI and path utilities with dynamic validation
################################################################################
require 'ruzzy'

# Suppress warnings
$VERBOSE = nil
module ::Kernel
  def warn(*args); end
end

require 'carrierwave'
require 'tempfile'

# Configure i18n to avoid locale enforcement issues
require 'i18n'
I18n.enforce_available_locales = false
I18n.default_locale = :en
I18n.available_locales = [:en]

if defined?(ActiveSupport::Deprecation)
  ActiveSupport.deprecator.behavior = :silence rescue nil
end

Signal.trap('ALRM') { }

EXTENSIONS = %w[jpg jpeg png gif webp pdf txt csv json xml html bin]

# Create uploader with custom store_dir and extension validation
def create_path_uploader(store_path, cache_path, allowed_ext)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ExtensionAllowlist

    storage :file

    define_method(:store_dir) { store_path }
    define_method(:cache_dir) { cache_path }
    define_method(:extension_allowlist) { allowed_ext }
  end
end

# Create uploader with filename override and extension validation
def create_filename_uploader(custom_filename, allowed_ext)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ExtensionAllowlist

    storage :file

    define_method(:store_dir) { '/tmp/cw_fuzz_store' }
    define_method(:cache_dir) { '/tmp/cw_fuzz_cache' }
    define_method(:extension_allowlist) { allowed_ext }

    define_method(:filename) do
      custom_filename if original_filename
    end
  end
end

test_one_input = lambda do |data|
  return 0 if data.length < 3

  begin
    op_type = data.getbyte(0) % 8

    case op_type
    when 0
      # Test path encoding utility with different extensions
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      allowed = [EXTENSIONS[ext_idx]]
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      paths = [
        "/normal/path/file.#{test_ext}",
        "/path with spaces/file.#{test_ext}",
        "/path%20encoded/file.#{test_ext}",
        "/../../../etc/passwd",
        "/unicode/\u4E2D\u6587.#{test_ext}",
        "/special/<>&\"/file.#{test_ext}",
      ]
      path_idx = data.getbyte(3) % paths.size
      CarrierWave::Utilities::Uri.encode_path(paths[path_idx]) rescue nil

      # Also test with uploader
      uploader_class = create_path_uploader('/tmp/cw_fuzz_store', '/tmp/cw_fuzz_cache', allowed)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['path', ".#{test_ext}"])
      tempfile.write(data[4..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 1
      # Test custom store_dir paths with dynamic validation
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      store_paths = [
        '/tmp/uploads',
        '/tmp/../etc',
        '/tmp/uploads/../../../etc',
        '/tmp/uploads/sub/dir',
      ]
      store_path = store_paths[data.getbyte(3) % store_paths.size]

      uploader_class = create_path_uploader(store_path, '/tmp/cw_cache', [EXTENSIONS[ext_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['store', ".#{test_ext}"])
      tempfile.write(data[4..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil
      uploader.url rescue nil

      tempfile.close
      tempfile.unlink

    when 2
      # Test custom filename through uploader with dynamic validation
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      filenames = [
        "simple.#{EXTENSIONS[ext_idx]}",
        "../../../etc/passwd",
        ".hidden",
        "UPPER.#{EXTENSIONS[ext_idx].upcase}",
        "multi.ext.#{EXTENSIONS[ext_idx]}",
      ]
      filename = filenames[data.getbyte(3) % filenames.size]

      uploader_class = create_filename_uploader(filename, [EXTENSIONS[ext_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['fn', ".#{test_ext}"])
      tempfile.write(data[4..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil
      uploader.url rescue nil

      tempfile.close
      tempfile.unlink

    when 3
      # Test retrieve_from_store with various identifiers
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      identifiers = [
        "file.#{test_ext}",
        "../file.#{test_ext}",
        "subdir/file.#{test_ext}",
        "",
        "." * 50 + ".#{test_ext}",
      ]
      identifier = identifiers[data.getbyte(3) % identifiers.size]

      uploader_class = create_path_uploader('/tmp/cw_fuzz_store', '/tmp/cw_fuzz_cache', [EXTENSIONS[ext_idx]])
      uploader = uploader_class.new
      uploader.retrieve_from_store!(identifier) rescue nil
      uploader.url rescue nil

    when 4
      # Test retrieve_from_cache with various cache names
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      cache_names = [
        "12345-1234-0001-1234/file.#{test_ext}",
        "../../../etc/passwd",
        "invalid",
        "",
        "a" * 100 + "/file.#{test_ext}",
      ]
      cache_name = cache_names[data.getbyte(3) % cache_names.size]

      uploader_class = create_path_uploader('/tmp/cw_fuzz_store', '/tmp/cw_fuzz_cache', [EXTENSIONS[ext_idx]])
      uploader = uploader_class.new
      uploader.retrieve_from_cache!(cache_name) rescue nil

    when 5
      # Test URL generation with different extensions
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_path_uploader('/tmp/cw_fuzz_store', '/tmp/cw_fuzz_cache', [EXTENSIONS[ext_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['url', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.url rescue nil
      uploader.store! rescue nil
      uploader.url rescue nil

      tempfile.close
      tempfile.unlink

    when 6
      # Test with regex extension patterns
      patterns = [/jpe?g/i, /png|gif/i, /\Apdf\z/i, /^txt$/i, /\A[a-z]{3,4}\z/i]
      pattern_idx = data.getbyte(1) % patterns.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = Class.new(CarrierWave::Uploader::Base) do
        include CarrierWave::Uploader::ExtensionAllowlist
        storage :file
        define_method(:store_dir) { '/tmp/cw_fuzz_store' }
        define_method(:cache_dir) { '/tmp/cw_fuzz_cache' }
        define_method(:extension_allowlist) { [patterns[pattern_idx]] }
      end
      uploader = uploader_class.new

      tempfile = Tempfile.new(['regex', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil

      tempfile.close
      tempfile.unlink

    when 7
      # Test cache_id generation with multiple uploads
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_path_uploader('/tmp/cw_fuzz_store', '/tmp/cw_fuzz_cache', [EXTENSIONS[ext_idx]])

      # Cache multiple files to exercise cache_id generation
      2.times do |i|
        uploader = uploader_class.new
        tempfile = Tempfile.new(["multi#{i}", ".#{test_ext}"])
        tempfile.write("content #{i} #{data[3..-1]}")
        tempfile.rewind

        uploader.cache!(tempfile) rescue nil
        uploader.cache_name rescue nil

        tempfile.close
        tempfile.unlink
      end
    end

  rescue StandardError
    # Expected
  ensure
    FileUtils.rm_rf('/tmp/cw_fuzz_store') rescue nil
    FileUtils.rm_rf('/tmp/cw_fuzz_cache') rescue nil
    FileUtils.rm_rf('/tmp/cw_cache') rescue nil
  end

  return 0
end

Ruzzy.fuzz(test_one_input)
