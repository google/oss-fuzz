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
# Fuzzer for CarrierWave Uploader with dynamic validation
################################################################################
require 'ruzzy'

# Suppress warnings
$VERBOSE = nil
module ::Kernel
  def warn(*args); end
end

require 'carrierwave'
require 'tempfile'
require 'stringio'
require 'fileutils'

# Configure i18n to avoid locale enforcement issues
require 'i18n'
I18n.enforce_available_locales = false
I18n.default_locale = :en
I18n.available_locales = [:en]

if defined?(ActiveSupport::Deprecation)
  ActiveSupport.deprecator.behavior = :silence rescue nil
end

Signal.trap('ALRM') { }

FUZZ_ROOT = '/tmp/cw_fuzz'
FileUtils.mkdir_p(FUZZ_ROOT)

EXTENSIONS = %w[jpg jpeg png gif webp pdf txt csv json xml html bin dat exe php]
CONTENT_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf', 'application/octet-stream']

# Create uploader with dynamic extension validation
def create_ext_uploader(allowed_ext)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ExtensionAllowlist

    storage :file

    define_method(:root) { FUZZ_ROOT }
    define_method(:store_dir) { 'uploads' }
    define_method(:cache_dir) { 'cache' }
    define_method(:extension_allowlist) { allowed_ext }
  end
end

# Create uploader with content type validation
def create_content_type_uploader(allowed_types)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ContentTypeAllowlist

    storage :file

    define_method(:root) { FUZZ_ROOT }
    define_method(:store_dir) { 'uploads' }
    define_method(:cache_dir) { 'cache' }
    define_method(:content_type_allowlist) { allowed_types }
  end
end

# Create uploader with file size validation
def create_size_uploader(min_size, max_size)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::FileSize

    storage :file

    define_method(:root) { FUZZ_ROOT }
    define_method(:store_dir) { 'uploads' }
    define_method(:cache_dir) { 'cache' }
    define_method(:size_range) { min_size..max_size }
  end
end

# Create uploader with versions
def create_versioned_uploader(allowed_ext)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ExtensionAllowlist

    storage :file

    define_method(:root) { FUZZ_ROOT }
    define_method(:store_dir) { 'uploads' }
    define_method(:cache_dir) { 'cache' }
    define_method(:extension_allowlist) { allowed_ext }

    version :thumb
    version :small
  end
end

test_one_input = lambda do |data|
  return 0 if data.length < 3

  begin
    op_type = data.getbyte(0) % 10

    case op_type
    when 0
      # Basic cache and store with dynamic extension validation
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_ext_uploader([EXTENSIONS[allowed_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['basic', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.cached? rescue nil
      uploader.store! rescue nil
      uploader.url rescue nil

      tempfile.close
      tempfile.unlink

    when 1
      # Test with multiple allowed extensions
      num_ext = (data.getbyte(1) % 4) + 1
      allowed = num_ext.times.map { |i| EXTENSIONS[data.getbyte(2 + i) % EXTENSIONS.size] }
      test_ext = EXTENSIONS[data.getbyte(6) % EXTENSIONS.size]

      uploader_class = create_ext_uploader(allowed)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['multi', ".#{test_ext}"])
      tempfile.write(data[7..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil

      tempfile.close
      tempfile.unlink

    when 2
      # Versioned uploader with dynamic validation
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_versioned_uploader([EXTENSIONS[allowed_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['version', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.thumb rescue nil
      uploader.small rescue nil
      uploader.versions rescue nil
      uploader.store! rescue nil

      tempfile.close
      tempfile.unlink

    when 3
      # Content type validation
      ct_idx = data.getbyte(1) % CONTENT_TYPES.size
      test_ct = CONTENT_TYPES[data.getbyte(2) % CONTENT_TYPES.size]

      uploader_class = create_content_type_uploader([CONTENT_TYPES[ct_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['ct', '.bin'])
      tempfile.write(data[3..-1])
      tempfile.rewind

      hash = {tempfile: tempfile, filename: 'test.bin', content_type: test_ct}
      uploader.cache!(hash) rescue nil
      uploader.store! rescue nil

      tempfile.close
      tempfile.unlink

    when 4
      # Size validation
      min_size = data.getbyte(1) * 5
      max_size = min_size + (data.getbyte(2) * 50) + 10
      test_ext = EXTENSIONS[data.getbyte(3) % EXTENSIONS.size]

      uploader_class = create_size_uploader(min_size, max_size)
      uploader = uploader_class.new

      # Write variable size content
      content_size = (data.getbyte(4) * 3) + 1
      tempfile = Tempfile.new(['size', ".#{test_ext}"])
      tempfile.write("x" * content_size)
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil

      tempfile.close
      tempfile.unlink

    when 5
      # Remove operation with dynamic validation
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      allowed_ext = EXTENSIONS[allowed_idx]

      uploader_class = create_ext_uploader([allowed_ext])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['remove', ".#{allowed_ext}"])
      tempfile.write(data[2..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil
      uploader.remove! rescue nil
      uploader.blank? rescue nil

      tempfile.close
      tempfile.unlink

    when 6
      # File operations on cached file
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      allowed_ext = EXTENSIONS[allowed_idx]

      uploader_class = create_ext_uploader([allowed_ext])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['ops', ".#{allowed_ext}"])
      tempfile.write(data[2..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil

      if uploader.file
        uploader.file.read rescue nil
        uploader.file.size rescue nil
        uploader.file.content_type rescue nil
        uploader.file.filename rescue nil
        uploader.file.extension rescue nil
      end

      tempfile.close
      tempfile.unlink

    when 7
      # Recreate versions with dynamic validation
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_versioned_uploader([EXTENSIONS[allowed_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['recreate', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil
      uploader.recreate_versions! rescue nil

      tempfile.close
      tempfile.unlink

    when 8
      # Test with regex extension patterns
      patterns = [/jpe?g/i, /png|gif/i, /\Apdf\z/i, /^txt$/i, /\A[a-z]{3,4}\z/i]
      pattern_idx = data.getbyte(1) % patterns.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_ext_uploader([patterns[pattern_idx]])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['regex', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil

      tempfile.close
      tempfile.unlink

    when 9
      # Multiple operations sequence
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      allowed_ext = EXTENSIONS[allowed_idx]

      uploader_class = create_ext_uploader([allowed_ext])
      uploader = uploader_class.new

      tempfile = Tempfile.new(['multi', ".#{allowed_ext}"])
      tempfile.write(data[2..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.cache_name rescue nil
      uploader.cached? rescue nil
      uploader.present? rescue nil
      uploader.blank? rescue nil
      uploader.to_s rescue nil
      uploader.store! rescue nil
      uploader.url rescue nil

      tempfile.close
      tempfile.unlink
    end

  rescue StandardError
    # Expected
  ensure
    FileUtils.rm_rf(File.join(FUZZ_ROOT, 'uploads')) rescue nil
    FileUtils.rm_rf(File.join(FUZZ_ROOT, 'cache')) rescue nil
  end

  return 0
end

Ruzzy.fuzz(test_one_input)
