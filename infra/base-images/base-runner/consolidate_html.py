#!/usr/bin/env python3
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
"""
Consolidates a SimpleCov HTML report into a single standalone HTML file
by inlining all CSS, JavaScript, and images as data URIs.
"""

import base64
import os
import re
import sys


def get_mime_type(file_path):
  """Determine MIME type based on file extension."""
  ext = os.path.splitext(file_path)[1].lower()
  mime_types = {
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon',
  }
  return mime_types.get(ext, 'application/octet-stream')


def inline_css_images(css_content, css_dir):
  """Inline images referenced in CSS using url()."""

  def replace_url(match):
    img_href = match.group(1).strip('\'"')
    img_path = os.path.join(css_dir, img_href)
    if os.path.isfile(img_path):
      mime_type = get_mime_type(img_path)
      with open(img_path, 'rb') as f:
        data = base64.b64encode(f.read()).decode('utf-8')
      return f'url(data:{mime_type};base64,{data})'
    return match.group(0)

  return re.sub(r'url\([\'"]?([^\'")\s]+)[\'"]?\)', replace_url, css_content)


def inline_file(html, base_path):
  """Inline all external resources (CSS, JS, images) into the HTML."""

  # Inline CSS files
  def replace_css(match):
    href = match.group(1)
    css_path = os.path.join(base_path, href)
    if os.path.isfile(css_path):
      with open(css_path, 'r', encoding='utf-8') as f:
        css_content = f.read()
      # Inline images within CSS
      css_dir = os.path.dirname(css_path)
      css_content = inline_css_images(css_content, css_dir)
      return f'<style>{css_content}</style>'
    return match.group(0)

  html = re.sub(r'<link[^>]+href=[\'"]([^\'"]+\.css)[\'"][^>]*>',
                replace_css,
                html,
                flags=re.IGNORECASE)

  # Inline JavaScript files
  def replace_js(match):
    src = match.group(1)
    js_path = os.path.join(base_path, src)
    if os.path.isfile(js_path):
      with open(js_path, 'r', encoding='utf-8') as f:
        js_content = f.read()
      return f"<script type='text/javascript'>{js_content}</script>"
    return match.group(0)

  html = re.sub(r'<script[^>]+src=[\'"]([^\'"]+\.js)[\'"][^>]*></script>',
                replace_js,
                html,
                flags=re.IGNORECASE)

  # Inline images
  def replace_img(match):
    full_tag = match.group(0)
    src_match = re.search(r'src=[\'"]([^\'"]+)[\'"]', full_tag)
    if not src_match:
      return full_tag

    src = src_match.group(1)
    if src.startswith('data:'):
      return full_tag

    img_path = os.path.join(base_path, src)
    if os.path.isfile(img_path):
      mime_type = get_mime_type(img_path)
      with open(img_path, 'rb') as f:
        data = base64.b64encode(f.read()).decode('utf-8')
      return re.sub(r'src=[\'"]([^\'"]+)[\'"]',
                    f"src='data:{mime_type};base64,{data}'", full_tag)
    return full_tag

  html = re.sub(r'<img[^>]+src=[\'"][^\'"]+[\'"][^>]*>',
                replace_img,
                html,
                flags=re.IGNORECASE)

  # Inline favicon
  def replace_favicon(match):
    full_tag = match.group(0)
    href_match = re.search(r'href=[\'"]([^\'"]+)[\'"]', full_tag)
    if not href_match:
      return full_tag

    href = href_match.group(1)
    icon_path = os.path.join(base_path, href)
    if os.path.isfile(icon_path):
      mime_type = get_mime_type(icon_path)
      with open(icon_path, 'rb') as f:
        data = base64.b64encode(f.read()).decode('utf-8')
      return re.sub(r'href=[\'"]([^\'"]+)[\'"]',
                    f"href='data:{mime_type};base64,{data}'", full_tag)
    return full_tag

  html = re.sub(r'<link[^>]+rel=[\'"]icon[\'"][^>]*>',
                replace_favicon,
                html,
                flags=re.IGNORECASE)

  return html


def main():
  if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <input_html_path> <output_html_path>")
    sys.exit(1)

  input_path = sys.argv[1]
  output_path = sys.argv[2]

  if not os.path.isfile(input_path):
    print(f"Error: Input file not found: {input_path}")
    sys.exit(1)

  base_path = os.path.dirname(input_path)

  with open(input_path, 'r', encoding='utf-8') as f:
    html = f.read()

  print(f"Consolidating {input_path}...")
  html = inline_file(html, base_path)

  with open(output_path, 'w', encoding='utf-8') as f:
    f.write(html)

  size_mb = os.path.getsize(output_path) / 1024 / 1024
  print(f"Created standalone HTML: {output_path}")
  print(f"Size: {size_mb:.1f}MB")


if __name__ == '__main__':
  main()
