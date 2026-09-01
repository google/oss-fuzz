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
# Fuzzer for CarrierWave::SanitizedFile with dynamic file operations
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

# Configure i18n to avoid locale enforcement issues
require 'i18n'
I18n.enforce_available_locales = false
I18n.default_locale = :en
I18n.available_locales = [:en]

if defined?(ActiveSupport::Deprecation)
  ActiveSupport.deprecator.behavior = :silence rescue nil
end

Signal.trap('ALRM') { }

EXTENSIONS = %w[jpg jpeg png gif webp pdf txt csv json xml html bin dat exe php]

# Create uploader with dynamic extension validation
def create_dynamic_uploader(allowed_ext, min_size, max_size)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ExtensionAllowlist
    include CarrierWave::Uploader::FileSize

    storage :file

    define_method(:extension_allowlist) { allowed_ext }
    define_method(:size_range) { min_size..max_size }
    define_method(:store_dir) { '/tmp/cw_fuzz_store' }
    define_method(:cache_dir) { '/tmp/cw_fuzz_cache' }
  end
end

test_one_input = lambda do |data|
  return 0 if data.length < 3

  begin
    op_type = data.getbyte(0) % 8

    case op_type
    when 0
      # Test SanitizedFile with StringIO - dynamic extension validation
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      allowed = [EXTENSIONS[allowed_idx]]
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_dynamic_uploader(allowed, 0, 10000)
      uploader = uploader_class.new

      content = data[3..-1].to_s
      io = StringIO.new(content)
      file = CarrierWave::SanitizedFile.new(io)
      file.instance_variable_set(:@original_filename, "test.#{test_ext}")

      uploader.cache!(file) rescue nil

    when 1
      # Test with multiple allowed extensions
      num_ext = (data.getbyte(1) % 4) + 1
      allowed = num_ext.times.map { |i| EXTENSIONS[data.getbyte(2 + i) % EXTENSIONS.size] }
      test_ext = EXTENSIONS[data.getbyte(6) % EXTENSIONS.size]

      uploader_class = create_dynamic_uploader(allowed, 0, 10000)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['test', ".#{test_ext}"])
      tempfile.write(data[7..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 2
      # Test with file size validation
      min_size = data.getbyte(1) * 5
      max_size = min_size + (data.getbyte(2) * 50) + 10
      test_ext = EXTENSIONS[data.getbyte(3) % EXTENSIONS.size]

      uploader_class = create_dynamic_uploader([test_ext], min_size, max_size)
      uploader = uploader_class.new

      content_size = (data.getbyte(4) * 3) + 1
      content = "x" * content_size

      tempfile = Tempfile.new(['size', ".#{test_ext}"])
      tempfile.write(content)
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 3
      # Test with hash input (rack upload simulation)
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_dynamic_uploader([EXTENSIONS[allowed_idx]], 0, 10000)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['upload', '.tmp'])
      tempfile.write(data[3..-1])
      tempfile.rewind

      content_types = ['image/jpeg', 'image/png', 'text/plain', 'application/pdf']
      ct = content_types[data.getbyte(3) % content_types.size]

      hash = {tempfile: tempfile, filename: "upload.#{test_ext}", content_type: ct}
      uploader.cache!(hash) rescue nil
      tempfile.close
      tempfile.unlink

    when 4
      # Test store operation with dynamic validation
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = create_dynamic_uploader([EXTENSIONS[allowed_idx]], 0, 10000)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['store', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil
      tempfile.close
      tempfile.unlink

    when 5
      # Test with various filenames
      filenames = [
        "normal.jpg", "../path.jpg", "test\x00.jpg", ".htaccess",
        "double.ext.jpg", "UPPER.JPG", "spaces in.jpg", "unicode\u4E2D.jpg"
      ]
      allowed_idx = data.getbyte(1) % EXTENSIONS.size
      filename_idx = data.getbyte(2) % filenames.size

      uploader_class = create_dynamic_uploader([EXTENSIONS[allowed_idx]], 0, 10000)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['fn', '.tmp'])
      tempfile.write(data[3..-1])
      tempfile.rewind

      hash = {tempfile: tempfile, filename: filenames[filename_idx], content_type: 'image/jpeg'}
      uploader.cache!(hash) rescue nil
      tempfile.close
      tempfile.unlink

    when 6
      # Test regex pattern matching
      patterns = [/jpe?g/i, /png|gif/i, /\Apdf\z/i, /^(doc|xls)x?$/i, /\A[a-z]{3}\z/i]
      pattern_idx = data.getbyte(1) % patterns.size
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]

      uploader_class = Class.new(CarrierWave::Uploader::Base) do
        include CarrierWave::Uploader::ExtensionAllowlist
        storage :file
        define_method(:extension_allowlist) { [patterns[pattern_idx]] }
        define_method(:store_dir) { '/tmp/cw_fuzz_store' }
        define_method(:cache_dir) { '/tmp/cw_fuzz_cache' }
      end
      uploader = uploader_class.new

      tempfile = Tempfile.new(['regex', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 7
      # Test remove operation
      allowed_ext = EXTENSIONS[data.getbyte(1) % EXTENSIONS.size]

      uploader_class = create_dynamic_uploader([allowed_ext], 0, 10000)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['remove', ".#{allowed_ext}"])
      tempfile.write(data[2..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      uploader.store! rescue nil
      uploader.remove! rescue nil
      tempfile.close
      tempfile.unlink
    end

  rescue StandardError
    # Expected
  ensure
    FileUtils.rm_rf('/tmp/cw_fuzz_store') rescue nil
    FileUtils.rm_rf('/tmp/cw_fuzz_cache') rescue nil
  end

  return 0
end

Ruzzy.fuzz(test_one_input)
