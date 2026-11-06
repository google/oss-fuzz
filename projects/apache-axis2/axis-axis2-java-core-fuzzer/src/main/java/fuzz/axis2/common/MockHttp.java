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

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal in-memory servlet request/response, built from dynamic proxies so that every
 * HttpServletRequest method has a sane answer. Mirrors what Tomcat hands AxisServlet:
 * getRequestURI() is the RAW (undecoded, unnormalised) path, as in a real container.
 */
public final class MockHttp {

    public static final String CONTEXT_PATH = "/axis2";
    public static final int MAX_RESPONSE = 32 * 1024 * 1024;

    private MockHttp() {
    }

    /** A request as the fuzzer describes it. */
    public static final class Req {
        public String method = "POST";
        public String rawUri = "/axis2/services/FuzzService";
        public String query; // without '?', may be null
        public final Map<String, List<String>> headers = new LinkedHashMap<>();
        public byte[] body = new byte[0];
        public boolean secure = false;

        public Req header(String name, String value) {
            if (name != null && value != null) {
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
            }
            return this;
        }

        String first(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                    return e.getValue().get(0);
                }
            }
            return null;
        }

        List<String> all(String name) {
            List<String> out = new ArrayList<>();
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    out.addAll(e.getValue());
                }
            }
            return out;
        }
    }

    /** Counts how many body bytes the server actually pulled from the transport. */
    public static final class CountingInput extends ServletInputStream {
        private final byte[] data;
        private int pos;
        public long pulled;

        CountingInput(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() {
            if (pos >= data.length) {
                return -1;
            }
            pulled++;
            return data[pos++] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (len == 0) {
                return 0;
            }
            if (pos >= data.length) {
                return -1;
            }
            int n = Math.min(len, data.length - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            pulled += n;
            return n;
        }

        @Override
        public int available() {
            return data.length - pos;
        }

        @Override
        public boolean isFinished() {
            return pos >= data.length;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
        }
    }

    /** Captured response. Output beyond MAX_RESPONSE is counted but not stored. */
    public static final class Resp {
        public int status = 200;
        public String contentType;
        public final Map<String, List<String>> headers = new LinkedHashMap<>();
        public final ByteArrayOutputStream body = new ByteArrayOutputStream();
        public long written;
        public boolean committed;

        public String bodyString() {
            return body.toString(StandardCharsets.ISO_8859_1);
        }
    }

    private static final class CapturingOutput extends ServletOutputStream {
        private final Resp resp;

        CapturingOutput(Resp resp) {
            this.resp = resp;
        }

        @Override
        public void write(int b) {
            resp.written++;
            resp.committed = true;
            if (resp.body.size() < MAX_RESPONSE) {
                resp.body.write(b);
            }
        }

        @Override
        public void write(byte[] b, int off, int len) {
            resp.written += len;
            resp.committed = true;
            int room = MAX_RESPONSE - resp.body.size();
            if (room > 0) {
                resp.body.write(b, off, Math.min(room, len));
            }
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {
        }
    }

    public static final class Exchange {
        public final Req req;
        public final Resp resp = new Resp();
        public final CountingInput input;
        public final HttpServletRequest request;
        public final HttpServletResponse response;

        Exchange(Req req, ServletContext ctx) {
            this.req = req;
            this.input = new CountingInput(req.body);
            this.request = request(req, input, ctx);
            this.response = response(resp);
        }
    }

    public static Exchange exchange(Req req, ServletContext ctx) {
        return new Exchange(req, ctx);
    }

    static String pathAfterContext(String rawUri) {
        return rawUri.startsWith(CONTEXT_PATH) ? rawUri.substring(CONTEXT_PATH.length()) : rawUri;
    }

    private static HttpServletRequest request(Req req, CountingInput in, ServletContext ctx) {
        Map<String, Object> attrs = new HashMap<>();
        HttpSession[] session = new HttpSession[1];
        InvocationHandler h = (proxy, m, args) -> {
            String n = m.getName();
            switch (n) {
                case "getMethod": return req.method;
                case "getRequestURI": return req.rawUri;
                case "getQueryString": return req.query;
                case "getRequestURL": return new StringBuffer((req.secure ? "https" : "http")
                        + "://localhost:8080" + req.rawUri);
                case "getContextPath": return CONTEXT_PATH;
                case "getServletPath": return "/services";
                case "getPathInfo": {
                    String p = pathAfterContext(req.rawUri);
                    return p.startsWith("/services") ? p.substring("/services".length()) : null;
                }
                case "getContentType": return req.first("Content-Type");
                case "getContentLength": {
                    String cl = req.first("Content-Length");
                    try { return cl == null ? req.body.length : Integer.parseInt(cl.trim()); }
                    catch (NumberFormatException e) { return -1; }
                }
                case "getContentLengthLong": {
                    String cl = req.first("Content-Length");
                    try { return cl == null ? (long) req.body.length : Long.parseLong(cl.trim()); }
                    catch (NumberFormatException e) { return -1L; }
                }
                case "getCharacterEncoding": {
                    String ct = req.first("Content-Type");
                    if (ct == null) return null;
                    int i = ct.toLowerCase(Locale.ROOT).indexOf("charset=");
                    if (i < 0) return null;
                    String cs = ct.substring(i + 8);
                    int semi = cs.indexOf(';');
                    if (semi >= 0) cs = cs.substring(0, semi);
                    return cs.replace("\"", "").trim();
                }
                case "getHeader": return req.first((String) args[0]);
                case "getHeaders": return Collections.enumeration(req.all((String) args[0]));
                case "getHeaderNames": return Collections.enumeration(new ArrayList<>(req.headers.keySet()));
                case "getIntHeader": {
                    String v = req.first((String) args[0]);
                    return v == null ? -1 : Integer.parseInt(v.trim());
                }
                case "getDateHeader": return -1L;
                case "getInputStream": return in;
                case "getReader": return new java.io.BufferedReader(
                        new java.io.InputStreamReader(in, StandardCharsets.UTF_8));
                case "getScheme": return req.secure ? "https" : "http";
                case "isSecure": return req.secure;
                case "getServerName": return "localhost";
                case "getServerPort": return 8080;
                case "getLocalPort": return 8080;
                case "getRemotePort": return 54321;
                case "getRemoteAddr": return "127.0.0.1";
                case "getRemoteHost": return "127.0.0.1";
                case "getLocalAddr": return "127.0.0.1";
                case "getLocalName": return "localhost";
                case "getProtocol": return "HTTP/1.1";
                case "getLocale": return Locale.US;
                case "getLocales": return Collections.enumeration(List.of(Locale.US));
                case "getAttribute": return attrs.get(args[0]);
                case "setAttribute": attrs.put((String) args[0], args[1]); return null;
                case "removeAttribute": attrs.remove(args[0]); return null;
                case "getAttributeNames": return Collections.enumeration(new ArrayList<>(attrs.keySet()));
                case "getParameter": return null;
                case "getParameterValues": return null;
                case "getParameterNames": return Collections.emptyEnumeration();
                case "getParameterMap": return Collections.emptyMap();
                case "getServletContext": return ctx;
                case "getSession": {
                    boolean create = args == null || args.length == 0 || (Boolean) args[0];
                    if (session[0] == null && create) session[0] = session();
                    return session[0];
                }
                case "getRequestedSessionId": return null;
                case "getCookies": return null;
                case "getAuthType": return null;
                case "getRemoteUser": return null;
                case "getUserPrincipal": return null;
                case "isUserInRole": return false;
                case "getRequestDispatcher": return dispatcher();
                case "getDispatcherType": return jakarta.servlet.DispatcherType.REQUEST;
                case "isAsyncSupported": return false;
                case "isAsyncStarted": return false;
                case "setCharacterEncoding": return null;
                case "toString": return "MockRequest[" + req.method + " " + req.rawUri + "]";
                case "hashCode": return System.identityHashCode(proxy);
                case "equals": return proxy == args[0];
                default: return defaultValue(m);
            }
        };
        return (HttpServletRequest) Proxy.newProxyInstance(MockHttp.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class}, h);
    }

    private static HttpServletResponse response(Resp resp) {
        CapturingOutput out = new CapturingOutput(resp);
        PrintWriter[] writer = new PrintWriter[1];
        InvocationHandler h = (proxy, m, args) -> {
            String n = m.getName();
            switch (n) {
                case "getOutputStream": return out;
                case "getWriter":
                    if (writer[0] == null) {
                        writer[0] = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8), true);
                    }
                    return writer[0];
                case "setStatus": resp.status = (Integer) args[0]; return null;
                case "getStatus": return resp.status;
                case "sendError": resp.status = (Integer) args[0];
                    if (args.length > 1 && args[1] != null) out.write(((String) args[1]).getBytes(StandardCharsets.UTF_8));
                    return null;
                case "sendRedirect": resp.status = 302; resp.headers.put("Location", List.of(String.valueOf(args[0]))); return null;
                case "setContentType": resp.contentType = (String) args[0]; return null;
                case "getContentType": return resp.contentType;
                case "setHeader": resp.headers.put((String) args[0], new ArrayList<>(List.of(String.valueOf(args[1])))); return null;
                case "addHeader": resp.headers.computeIfAbsent((String) args[0], k -> new ArrayList<>()).add(String.valueOf(args[1])); return null;
                case "setIntHeader":
                case "addIntHeader":
                case "setDateHeader":
                case "addDateHeader": return null;
                case "containsHeader": return resp.headers.containsKey(args[0]);
                case "getHeader": { List<String> v = resp.headers.get(args[0]); return v == null || v.isEmpty() ? null : v.get(0); }
                case "getHeaders": { List<String> v = resp.headers.get(args[0]); return v == null ? List.of() : v; }
                case "getHeaderNames": return resp.headers.keySet();
                case "isCommitted": return resp.committed;
                case "getCharacterEncoding": return "UTF-8";
                case "getBufferSize": return 8192;
                case "flushBuffer": if (writer[0] != null) writer[0].flush(); return null;
                case "toString": return "MockResponse";
                case "hashCode": return System.identityHashCode(proxy);
                case "equals": return proxy == args[0];
                default: return defaultValue(m);
            }
        };
        return (HttpServletResponse) Proxy.newProxyInstance(MockHttp.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class}, h);
    }

    private static HttpSession session() {
        Map<String, Object> attrs = new HashMap<>();
        String id = "S" + System.nanoTime();
        InvocationHandler h = (proxy, m, args) -> {
            switch (m.getName()) {
                case "getId": return id;
                case "getAttribute": return attrs.get(args[0]);
                case "setAttribute": attrs.put((String) args[0], args[1]); return null;
                case "removeAttribute": attrs.remove(args[0]); return null;
                case "getAttributeNames": return Collections.enumeration(new ArrayList<>(attrs.keySet()));
                case "isNew": return true;
                case "hashCode": return System.identityHashCode(proxy);
                case "equals": return proxy == args[0];
                default: return defaultValue(m);
            }
        };
        return (HttpSession) Proxy.newProxyInstance(MockHttp.class.getClassLoader(),
                new Class<?>[] {HttpSession.class}, h);
    }

    private static Object dispatcher() {
        // JSP views of the listing agent are not rendered in-process; forward/include are no-ops.
        return Proxy.newProxyInstance(MockHttp.class.getClassLoader(),
                new Class<?>[] {jakarta.servlet.RequestDispatcher.class}, (p, m, a) -> defaultValue(m));
    }

    /** A ServletContext / ServletConfig pair holding a single attribute map. */
    public static ServletContext servletContext(Map<String, Object> attrs, String realPathRoot) {
        InvocationHandler h = (proxy, m, args) -> {
            switch (m.getName()) {
                case "getAttribute": return attrs.get(args[0]);
                case "setAttribute": attrs.put((String) args[0], args[1]); return null;
                case "removeAttribute": attrs.remove(args[0]); return null;
                case "getAttributeNames": return Collections.enumeration(new ArrayList<>(attrs.keySet()));
                case "getInitParameter": return null;
                case "getInitParameterNames": return Collections.emptyEnumeration();
                case "getContextPath": return CONTEXT_PATH;
                case "getRealPath": return realPathRoot + "/" + args[0];
                case "getServerInfo": return "MockContainer/1.0";
                case "getMajorVersion": return 6;
                case "getMinorVersion": return 0;
                case "getServletContextName": return "axis2";
                case "log": return null;
                case "getResource": return null;
                case "getResourceAsStream": return null;
                case "getMimeType": return null;
                case "getRequestDispatcher":
                case "getNamedDispatcher": return dispatcher();
                case "hashCode": return System.identityHashCode(proxy);
                case "equals": return proxy == args[0];
                default: return defaultValue(m);
            }
        };
        return (ServletContext) Proxy.newProxyInstance(MockHttp.class.getClassLoader(),
                new Class<?>[] {ServletContext.class}, h);
    }

    public static jakarta.servlet.ServletConfig servletConfig(ServletContext ctx) {
        InvocationHandler h = (proxy, m, args) -> {
            switch (m.getName()) {
                case "getServletContext": return ctx;
                case "getServletName": return "AxisServlet";
                case "getInitParameter": return null;
                case "getInitParameterNames": return Collections.emptyEnumeration();
                case "hashCode": return System.identityHashCode(proxy);
                case "equals": return proxy == args[0];
                default: return defaultValue(m);
            }
        };
        return (jakarta.servlet.ServletConfig) Proxy.newProxyInstance(MockHttp.class.getClassLoader(),
                new Class<?>[] {jakarta.servlet.ServletConfig.class}, h);
    }

    static Object defaultValue(Method m) {
        Class<?> r = m.getReturnType();
        if (!r.isPrimitive()) {
            return null;
        }
        if (r == boolean.class) return false;
        if (r == int.class) return 0;
        if (r == long.class) return 0L;
        if (r == void.class) return null;
        if (r == short.class) return (short) 0;
        if (r == byte.class) return (byte) 0;
        if (r == char.class) return (char) 0;
        if (r == float.class) return 0f;
        if (r == double.class) return 0d;
        return null;
    }
}
