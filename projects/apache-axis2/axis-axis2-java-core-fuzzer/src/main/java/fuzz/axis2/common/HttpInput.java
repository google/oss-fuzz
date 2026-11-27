// Copyright 2026 Google LLC
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

package fuzz.axis2.common;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Parses the fuzzer input as a raw HTTP/1.1 request:
 *
 *   METHOD SP request-target [SP HTTP/1.1] LF
 *   Header: value LF   (CRLF also accepted)
 *   ...
 *   LF
 *   body
 *
 * Pseudo-headers starting with "X-Fuzz-" steer the harness and are not passed to Axis2.
 * The body may contain one "@@R@@...@@E@@" segment that is repeated X-Fuzz-Repeat times,
 * so that a small input can describe a large request (body-limit harness).
 */
public final class HttpInput {

    public static final int MAX_HEADERS = 64;

    public final MockHttp.Req req = new MockHttp.Req();
    public String transport;      // X-Fuzz-Transport
    public String backend;        // X-Fuzz-Backend
    public int repeat;            // X-Fuzz-Repeat

    private HttpInput() {
    }

    public static HttpInput parse(byte[] data, int maxBody) {
        HttpInput in = new HttpInput();
        int pos = 0;
        int lineEnd = indexOf(data, (byte) '\n', pos);
        if (lineEnd < 0) {
            return null;
        }
        String requestLine = line(data, pos, lineEnd);
        pos = lineEnd + 1;
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            return null;
        }
        in.req.method = parts[0];
        String target = parts[1];
        int q = target.indexOf('?');
        if (q >= 0) {
            in.req.rawUri = target.substring(0, q);
            in.req.query = target.substring(q + 1);
        } else {
            in.req.rawUri = target;
            in.req.query = null;
        }
        int headers = 0;
        while (pos < data.length) {
            lineEnd = indexOf(data, (byte) '\n', pos);
            if (lineEnd < 0) {
                lineEnd = data.length;
            }
            String h = line(data, pos, lineEnd);
            pos = Math.min(lineEnd + 1, data.length);
            if (h.isEmpty()) {
                break;
            }
            int colon = h.indexOf(':');
            if (colon <= 0 || ++headers > MAX_HEADERS) {
                continue;
            }
            String name = h.substring(0, colon).trim();
            String value = h.substring(colon + 1).trim();
            String lname = name.toLowerCase(Locale.ROOT);
            if (lname.equals("x-fuzz-transport")) {
                in.transport = value;
            } else if (lname.equals("x-fuzz-backend")) {
                in.backend = value;
            } else if (lname.equals("x-fuzz-repeat")) {
                try {
                    in.repeat = Math.max(0, Math.min(Integer.parseInt(value), 1 << 20));
                } catch (NumberFormatException e) {
                    in.repeat = 0;
                }
            } else {
                in.req.header(name, value);
            }
        }
        byte[] body = new byte[data.length - pos];
        System.arraycopy(data, pos, body, 0, body.length);
        in.req.body = expand(body, in.repeat, maxBody);
        return in;
    }

    private static final byte[] R = "@@R@@".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] E = "@@E@@".getBytes(StandardCharsets.ISO_8859_1);

    static byte[] expand(byte[] body, int repeat, int maxBody) {
        int r = indexOf(body, R, 0);
        int e = r < 0 ? -1 : indexOf(body, E, r + R.length);
        if (r < 0 || e < 0) {
            return body.length > maxBody ? java.util.Arrays.copyOf(body, maxBody) : body;
        }
        int segLen = e - (r + R.length);
        long total = (long) r + (long) segLen * repeat + (body.length - (e + E.length));
        int out = (int) Math.min(total, maxBody);
        byte[] res = new byte[out];
        int w = 0;
        w = copy(body, 0, r, res, w);
        for (int i = 0; i < repeat && w < out && segLen > 0; i++) {
            w = copy(body, r + R.length, segLen, res, w);
        }
        copy(body, e + E.length, body.length - (e + E.length), res, w);
        return res;
    }

    private static int copy(byte[] src, int off, int len, byte[] dst, int w) {
        int n = Math.max(0, Math.min(len, dst.length - w));
        System.arraycopy(src, off, dst, w, n);
        return w + n;
    }

    private static String line(byte[] d, int from, int to) {
        int end = to;
        if (end > from && d[end - 1] == '\r') {
            end--;
        }
        return new String(d, from, end - from, StandardCharsets.ISO_8859_1);
    }

    private static int indexOf(byte[] d, byte b, int from) {
        for (int i = from; i < d.length; i++) {
            if (d[i] == b) return i;
        }
        return -1;
    }

    static int indexOf(byte[] d, byte[] pat, int from) {
        outer:
        for (int i = from; i <= d.length - pat.length; i++) {
            for (int j = 0; j < pat.length; j++) {
                if (d[i + j] != pat[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
