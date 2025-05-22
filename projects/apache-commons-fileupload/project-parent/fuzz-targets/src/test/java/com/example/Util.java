// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in co  mpliance with the License.
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
//////////////////////////////////////////////////////////////////////////////////

package com.example;

import org.apache.commons.fileupload2.FileItem;
import org.apache.commons.fileupload2.FileUpload;
import org.apache.commons.fileupload2.FileUploadException;
import org.apache.commons.fileupload2.disk.DiskFileItemFactory;
import org.apache.commons.fileupload2.portlet.PortletFileUpload;
import org.apache.commons.fileupload2.servlet.ServletFileUpload;
import org.apache.commons.fileupload2.servlet.ServletRequestContext;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Test utility methods.
 *
 * @since 1.4
 */
public class Util {

    public static List<FileItem> parseUpload(final FileUpload upload, final byte[] bytes) throws FileUploadException {
        return parseUpload(upload, bytes, Constants.CONTENT_TYPE);
    }

    public static List<FileItem> parseUpload(final FileUpload upload, final byte[] bytes, final String contentType)
            throws FileUploadException {
        final HttpServletRequest request = new MockHttpServletRequest(bytes, contentType);
        return upload.parseRequest(new ServletRequestContext(request));
    }

    public static List<FileItem> parseUpload(final FileUpload upload, final String content)
        throws UnsupportedEncodingException, FileUploadException {
        final byte[] bytes = content.getBytes(StandardCharsets.US_ASCII);
        return parseUpload(upload, bytes, Constants.CONTENT_TYPE);
    }

    /**
     * Return a list of {@link FileUpload} implementations for parameterized tests.
     * @return a list of {@link FileUpload} implementations
     */
    public static List<FileUpload> fileUploadImplementations() {
        return Arrays.asList(
                new ServletFileUpload(new DiskFileItemFactory()),
                new PortletFileUpload(new DiskFileItemFactory()));
    }
}
