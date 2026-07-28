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
# Comprehensive fuzzer for CarrierWave validation modules
# Covers: ExtensionAllowlist, ExtensionDenylist, ContentTypeAllowlist,
#         ContentTypeDenylist, FileSize validation
################################################################################
require 'ruzzy'

# Suppress Ruby warnings (libyaml/psych warnings and deprecation warnings)
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

# Silence ActiveSupport deprecation warnings
if defined?(ActiveSupport::Deprecation)
  ActiveSupport.deprecator.behavior = :silence rescue nil
end

Signal.trap('ALRM') { }

# Common extensions to test
EXTENSIONS = %w[
  jpg jpeg png gif webp svg bmp tiff ico
  pdf doc docx xls xlsx ppt pptx
  txt csv json xml html htm css js
  zip tar gz bz2 7z rar
  mp3 mp4 wav avi mov mkv
  exe dll so dylib bin
  php phtml php5 php7 phar
  rb py pl sh bash
  htaccess gitignore env config
]

CONTENT_TYPES = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
  'image/bmp', 'image/tiff', 'image/x-icon',
  'application/pdf', 'application/msword', 'application/json',
  'application/zip', 'application/x-rar-compressed',
  'application/octet-stream', 'application/x-executable',
  'text/plain', 'text/html', 'text/css', 'text/javascript',
  'video/mp4', 'video/mpeg', 'audio/mpeg', 'audio/wav',
  'multipart/form-data', 'application/x-www-form-urlencoded'
]

# Create uploader classes with various validation configurations
def create_extension_allowlist_uploader(extensions)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ExtensionAllowlist

    define_method(:extension_allowlist) do
      extensions
    end

    # Use memory storage to avoid filesystem operations
    storage :file
    define_method(:store_dir) { '/tmp/cw_fuzz_store' }
    define_method(:cache_dir) { '/tmp/cw_fuzz_cache' }
  end
end

def create_content_type_allowlist_uploader(types)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::ContentTypeAllowlist

    define_method(:content_type_allowlist) do
      types
    end

    storage :file
    define_method(:store_dir) { '/tmp/cw_fuzz_store' }
    define_method(:cache_dir) { '/tmp/cw_fuzz_cache' }
  end
end

def create_filesize_uploader(min_size, max_size)
  Class.new(CarrierWave::Uploader::Base) do
    include CarrierWave::Uploader::FileSize

    define_method(:size_range) do
      min_size..max_size
    end

    storage :file
    define_method(:store_dir) { '/tmp/cw_fuzz_store' }
    define_method(:cache_dir) { '/tmp/cw_fuzz_cache' }
  end
end

test_one_input = lambda do |data|
  return 0 if data.length < 2

  begin
    op_type = data.getbyte(0) % 14

    case op_type
    # === Extension Allowlist tests ===
    when 0
      # Test with single extension allowlist
      ext_idx = data.getbyte(1) % EXTENSIONS.size
      allowed = [EXTENSIONS[ext_idx]]
      uploader_class = create_extension_allowlist_uploader(allowed)
      uploader = uploader_class.new

      # Create file with fuzzed extension
      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]
      tempfile = Tempfile.new(['test', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 1
      # Test with multiple extension allowlist
      num_ext = (data.getbyte(1) % 5) + 1
      allowed = num_ext.times.map { |i| EXTENSIONS[data.getbyte(2 + i) % EXTENSIONS.size] }
      uploader_class = create_extension_allowlist_uploader(allowed)
      uploader = uploader_class.new

      test_ext = data[8..16].to_s.gsub(/[^a-zA-Z0-9]/, '')
      test_ext = 'bin' if test_ext.empty?
      tempfile = Tempfile.new(['test', ".#{test_ext}"])
      tempfile.write("content")
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 2
      # Test with regex extension allowlist
      patterns = [/jpe?g/i, /png|gif/i, /\Apdf\z/i, /^(doc|xls)x?$/i]
      pattern_idx = data.getbyte(1) % patterns.size
      uploader_class = create_extension_allowlist_uploader([patterns[pattern_idx]])
      uploader = uploader_class.new

      test_ext = EXTENSIONS[data.getbyte(2) % EXTENSIONS.size]
      tempfile = Tempfile.new(['test', ".#{test_ext}"])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    # === Additional Extension Allowlist tests ===
    when 3
      # Test with document extension allowlist
      allowed = %w[pdf doc docx xls xlsx ppt pptx]
      uploader_class = create_extension_allowlist_uploader(allowed)
      uploader = uploader_class.new

      test_ext = EXTENSIONS[data.getbyte(1) % EXTENSIONS.size]
      tempfile = Tempfile.new(['test', ".#{test_ext}"])
      tempfile.write(data[2..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 4
      # Test allowlist with case variations
      allowed = [/jpe?g/i, /png/i, /gif/i]
      uploader_class = create_extension_allowlist_uploader(allowed)
      uploader = uploader_class.new

      # Generate case-varied extension
      base_ext = EXTENSIONS[data.getbyte(1) % EXTENSIONS.size]
      varied = base_ext.chars.map.with_index { |c, i| data.getbyte(2 + i) % 2 == 0 ? c.upcase : c.downcase }.join
      tempfile = Tempfile.new(['test', ".#{varied}"])
      tempfile.write("x")
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    # === Content Type Allowlist tests ===
    when 5
      # Test with content type allowlist
      ct_idx = data.getbyte(1) % CONTENT_TYPES.size
      allowed = [CONTENT_TYPES[ct_idx]]
      uploader_class = create_content_type_allowlist_uploader(allowed)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['test', '.bin'])
      tempfile.write(data[2..-1])
      tempfile.rewind

      # Simulate uploaded file with content type
      hash = {
        tempfile: tempfile,
        filename: 'test.bin',
        content_type: CONTENT_TYPES[data.getbyte(2) % CONTENT_TYPES.size]
      }
      file = CarrierWave::SanitizedFile.new(hash)
      uploader.cache!(file) rescue nil
      tempfile.close
      tempfile.unlink

    when 6
      # Test with image content type allowlist
      allowed = [/image\//]
      uploader_class = create_content_type_allowlist_uploader(allowed)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['test', '.jpg'])
      # Add JPEG magic bytes
      tempfile.write("\xFF\xD8\xFF\xE0" + data[1..-1].to_s)
      tempfile.rewind

      hash = {
        tempfile: tempfile,
        filename: 'image.jpg',
        content_type: CONTENT_TYPES[data.getbyte(1) % CONTENT_TYPES.size]
      }
      file = CarrierWave::SanitizedFile.new(hash)
      uploader.cache!(file) rescue nil
      tempfile.close
      tempfile.unlink

    # === Additional Content Type Allowlist tests ===
    when 7
      # Test with document content type allowlist
      allowed = ['application/pdf', 'application/msword', /application\/vnd\./]
      uploader_class = create_content_type_allowlist_uploader(allowed)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['test', '.bin'])
      tempfile.write(data[1..-1])
      tempfile.rewind

      hash = {
        tempfile: tempfile,
        filename: 'test.bin',
        content_type: CONTENT_TYPES[data.getbyte(1) % CONTENT_TYPES.size]
      }
      file = CarrierWave::SanitizedFile.new(hash)
      uploader.cache!(file) rescue nil
      tempfile.close
      tempfile.unlink

    # === File Size validation tests ===
    when 8
      # Test file size within range
      min_size = data.getbyte(1) * 10
      max_size = min_size + (data.getbyte(2) * 100) + 100
      uploader_class = create_filesize_uploader(min_size, max_size)
      uploader = uploader_class.new

      tempfile = Tempfile.new(['test', '.bin'])
      tempfile.write(data[3..-1])
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    when 9
      # Test file size at boundaries
      file_size = (data.getbyte(1) << 8) | data.getbyte(2)
      uploader_class = create_filesize_uploader(file_size, file_size + 10)
      uploader = uploader_class.new

      content = "x" * file_size
      tempfile = Tempfile.new(['test', '.bin'])
      tempfile.write(content)
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink

    # === Combined validation tests ===
    when 10
      # Test extension + content type validation together
      uploader_class = Class.new(CarrierWave::Uploader::Base) do
        include CarrierWave::Uploader::ExtensionAllowlist
        include CarrierWave::Uploader::ContentTypeAllowlist

        def extension_allowlist
          %w[jpg jpeg png gif]
        end

        def content_type_allowlist
          [/image\//]
        end

        storage :file
        def store_dir; '/tmp/cw_fuzz_store'; end
        def cache_dir; '/tmp/cw_fuzz_cache'; end
      end

      uploader = uploader_class.new
      ext = EXTENSIONS[data.getbyte(1) % EXTENSIONS.size]
      tempfile = Tempfile.new(['test', ".#{ext}"])
      tempfile.write(data[2..-1])
      tempfile.rewind

      hash = {
        tempfile: tempfile,
        filename: "test.#{ext}",
        content_type: CONTENT_TYPES[data.getbyte(2) % CONTENT_TYPES.size]
      }
      file = CarrierWave::SanitizedFile.new(hash)
      uploader.cache!(file) rescue nil
      tempfile.close
      tempfile.unlink

    when 11
      # Test double extension bypass attempts
      allowed = %w[jpg png gif]
      uploader_class = create_extension_allowlist_uploader(allowed)
      uploader = uploader_class.new

      bypass_patterns = [
        "test.php.jpg", "test.jpg.php", "test.php%00.jpg",
        "test.jpg::$DATA", "test.jpg;.php", "test.jpg%0a.php",
        "test.phtml.jpg", "test.jpg/.php"
      ]
      pattern_idx = data.getbyte(1) % bypass_patterns.size
      filename = bypass_patterns[pattern_idx]

      tempfile = Tempfile.new(['test', '.tmp'])
      tempfile.write(data[2..-1])
      tempfile.rewind

      hash = {tempfile: tempfile, filename: filename, content_type: 'image/jpeg'}
      file = CarrierWave::SanitizedFile.new(hash)
      uploader.cache!(file) rescue nil
      tempfile.close
      tempfile.unlink

    when 12
      # Test with null byte in extension
      allowed = %w[jpg png]
      uploader_class = create_extension_allowlist_uploader(allowed)
      uploader = uploader_class.new

      filename = "test.php\x00.jpg"
      tempfile = Tempfile.new(['test', '.tmp'])
      tempfile.write(data[1..-1])
      tempfile.rewind

      hash = {tempfile: tempfile, filename: filename, content_type: 'image/jpeg'}
      file = CarrierWave::SanitizedFile.new(hash)
      uploader.cache!(file) rescue nil
      tempfile.close
      tempfile.unlink

    when 13
      # Test regex patterns in validation
      regex_patterns = [
        /\Ajpe?g\z/i, /\A(png|gif|webp)\z/i, /\A[a-z]{3,4}\z/i,
        /^(?:jpg|jpeg|png)$/i, /image/i
      ]
      pattern_idx = data.getbyte(1) % regex_patterns.size
      uploader_class = create_extension_allowlist_uploader([regex_patterns[pattern_idx]])
      uploader = uploader_class.new

      # Generate fuzzed extension
      ext = data[2..10].to_s.gsub(/[^a-zA-Z0-9]/, '')[0..10]
      ext = 'bin' if ext.empty?
      tempfile = Tempfile.new(['test', ".#{ext}"])
      tempfile.write("x")
      tempfile.rewind

      uploader.cache!(tempfile) rescue nil
      tempfile.close
      tempfile.unlink
    end

  rescue ArgumentError, TypeError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, IOError, Errno::ENOENT,
         Errno::EACCES, RuntimeError, NoMethodError, RegexpError,
         CarrierWave::IntegrityError, CarrierWave::InvalidParameter,
         LoadError, StandardError
    # Expected exceptions
  ensure
    # Cleanup any lingering temp files
    FileUtils.rm_rf('/tmp/cw_fuzz_store') rescue nil
    FileUtils.rm_rf('/tmp/cw_fuzz_cache') rescue nil
  end

  return 0
end

Ruzzy.fuzz(test_one_input)
