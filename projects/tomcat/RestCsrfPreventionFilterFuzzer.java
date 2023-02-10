// Copyright 2022 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import org.apache.catalina.filters.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.File;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.net.URL;
import java.net.HttpURLConnection;

import javax.xml.transform.stream.StreamSource;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.Context;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.BytesStreamer;
import org.apache.catalina.LifecycleException;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.codec.binary.Base64;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;


public class RestCsrfPreventionFilterFuzzer {
    public static final boolean USE_COOKIES = true;
    public static final boolean NO_COOKIES = !USE_COOKIES;

    public static final String METHOD_GET = "GET";
    public static final String METHOD_POST = "POST";

    public static final String HTTP_PREFIX = "http://localhost:";
    public static final String CONTEXT_PATH_LOGIN = "";
    public static final String URI_PROTECTED = "/services/*";
    public static final String URI_CSRF_PROTECTED = "/services/customers/*";
    public static final String LIST_CUSTOMERS = "/services/customers/";
    public static final String REMOVE_CUSTOMER = "/services/customers/removeCustomer";
    public static final String ADD_CUSTOMER = "/services/customers/addCustomer";
    public static final String REMOVE_ALL_CUSTOMERS = "/services/customers/removeAllCustomers";
    public static final String FILTER_INIT_PARAM = "pathsAcceptingParams";
    public static final String SERVLET_NAME = "TesterServlet";
    public static final String FILTER_NAME = "Csrf";

    public static final String CUSTOMERS_LIST_RESPONSE = "Customers list";
    public static final String CUSTOMER_REMOVED_RESPONSE = "Customer removed";
    public static final String CUSTOMER_ADDED_RESPONSE = "Customer added";

    public static final String INVALID_NONCE_1 = "invalid_nonce";
    public static final String INVALID_NONCE_2 = "";

    public static final String USER = "user";
    public static final String PWD = "pwd";
    public static final String ROLE = "role";
    public static final String METHOD = "BASIC";
    public static final BasicCredentials CREDENTIALS = new BasicCredentials(METHOD, USER, PWD);

    public static final String CLIENT_AUTH_HEADER = "authorization";
    public static final String SERVER_COOKIE_HEADER = "Set-Cookie";
    public static final String CLIENT_COOKIE_HEADER = "Cookie";

    public static final int SHORT_SESSION_TIMEOUT_MINS = 1;

    public static Tomcat tomcat;
    public static Context context;
    public static List<String> cookies = new ArrayList<>();
    public static String validNonce;

    public static void fuzzerTearDown() {
        try {
            tomcat.stop();
            tomcat.destroy();
            tomcat = null;
            System.gc();
        } catch (LifecycleException e) {
            throw new FuzzerSecurityIssueLow("Teardown Error!!");
        }
    }
    
    public static void fuzzerInitialize() {
        tomcat = new Tomcat();

        tomcat.setBaseDir("temp");
        Connector connector1 = tomcat.getConnector();
        connector1.setPort(0);

        tomcat.addUser(USER, PWD);
        tomcat.addRole(USER, ROLE);

        try {
            setUpApplication();   
        } catch (Exception e) {
            throw new FuzzerSecurityIssueLow("setUpApplication Error!");
        }

        try {
            tomcat.start();
        } catch (LifecycleException e) {
            throw new FuzzerSecurityIssueLow("Tomcat Start Error!");
        }
        
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String str1 = data.consumeString(500);
        String str2 = data.consumeRemainingAsString();

        try {
            String invalidbody = Constants.CSRF_REST_NONCE_HEADER_NAME + "=" + str1;
            
            doTest(METHOD_POST, REMOVE_ALL_CUSTOMERS, CREDENTIALS, invalidbody.getBytes(StandardCharsets.ISO_8859_1), USE_COOKIES, 
                HttpServletResponse.SC_FORBIDDEN, null, str2, true, Constants.CSRF_REST_NONCE_HEADER_REQUIRED_VALUE);
        } catch (Exception e) {
        }
        
    }

    public static void doTest(String method, String uri, BasicCredentials credentials, byte[] body,
            boolean useCookie, int expectedRC, String expectedResponse, String nonce,
            boolean expectCsrfRH, String expectedCsrfRHV) throws Exception {
        Map<String, List<String>> reqHeaders = new HashMap<>();
        Map<String, List<String>> respHeaders = new HashMap<>();

        addNonce(reqHeaders, nonce, n -> Objects.nonNull(n));

        if (useCookie) {
            addCookies(reqHeaders, l -> Objects.nonNull(l) && l.size() > 0);
        }

        addCredentials(reqHeaders, credentials, c -> Objects.nonNull(c));

        ByteChunk bc = new ByteChunk();
        int rc;
        if (METHOD_GET.equals(method)) {
            rc = getUrl(HTTP_PREFIX + tomcat.getConnector().getLocalPort() + uri, bc, reqHeaders, respHeaders);
        } else {
            rc = postUrl(body, HTTP_PREFIX + tomcat.getConnector().getLocalPort() + uri, bc, reqHeaders, respHeaders);
        }

        assert (rc == expectedRC || rc ==  HttpServletResponse.SC_BAD_REQUEST ): new FuzzerSecurityIssueLow("expectedRC not equal to rc!");

        if (expectedRC == HttpServletResponse.SC_OK) {
            assert expectedResponse.equals(bc.toString()) : new FuzzerSecurityIssueLow("expectedResponse not equals to bc.toString()");
            List<String> newCookies = respHeaders.get(SERVER_COOKIE_HEADER);
            saveCookies(newCookies, l -> Objects.nonNull(l) && l.size() > 0);
        }

        if (!expectCsrfRH) {
            assert respHeaders.get(Constants.CSRF_REST_NONCE_HEADER_NAME) == null : new FuzzerSecurityIssueLow("respHeaders.get(Constants.CSRF_REST_NONCE_HEADER_NAME) is not null!");
        } else {
            List<String> respHeaderValue = respHeaders.get(Constants.CSRF_REST_NONCE_HEADER_NAME); // Constants.CSRF_REST_NONCE_HEADER_NAME == X-CSRF-Token
            // assert respHeaderValue != null : new FuzzerSecurityIssueHigh("respHeaderValue is null!"); 
            if (Objects.nonNull(expectedCsrfRHV)) {
                assert respHeaderValue.contains(expectedCsrfRHV) : new FuzzerSecurityIssueLow("respHeaderValue does not contain expectedCsrfRHV!");
            } else {
                validNonce = respHeaderValue.get(0);
            }
        }
    }

    public static void saveCookies(List<String> newCookies, Predicate<List<String>> tester) {
        if (tester.test(newCookies)) {
            newCookies.forEach(h -> cookies.add(h.substring(0, h.indexOf(';'))));
        }
    }

    public static void addCookies(Map<String, List<String>> reqHeaders, Predicate<List<String>> tester) {
        if (tester.test(cookies)) {
            StringBuilder cookieHeader = new StringBuilder();
            boolean first = true;
            for (String cookie : cookies) {
                if (!first) {
                    cookieHeader.append(';');
                } else {
                    first = false;
                }
                cookieHeader.append(cookie);
            }
            addRequestHeader(reqHeaders, CLIENT_COOKIE_HEADER, cookieHeader.toString());
        }
    }

    public static void addNonce(Map<String, List<String>> reqHeaders, String nonce,
            Predicate<String> tester) {
        if (tester.test(nonce)) {
            addRequestHeader(reqHeaders, Constants.CSRF_REST_NONCE_HEADER_NAME, nonce);
        }
    }

    public static void addCredentials(Map<String, List<String>> reqHeaders, BasicCredentials credentials,
            Predicate<BasicCredentials> tester) {
        if (tester.test(credentials)) {
            addRequestHeader(reqHeaders, CLIENT_AUTH_HEADER, credentials.getCredentials());
        }
    }

    public static void addRequestHeader(Map<String, List<String>> reqHeaders, String key, String value) {
        List<String> valueList = new ArrayList<>(1);
        valueList.add(value);
        reqHeaders.put(key, valueList);
    }

    public static void setUpApplication() throws Exception {
        context = tomcat.addContext(CONTEXT_PATH_LOGIN, new File(".").getAbsolutePath());
        context.setSessionTimeout(SHORT_SESSION_TIMEOUT_MINS);

        Tomcat.addServlet(context, SERVLET_NAME, new TesterServlet());
        context.addServletMappingDecoded(URI_PROTECTED, SERVLET_NAME);

        FilterDef filterDef = new FilterDef();
        filterDef.setFilterName(FILTER_NAME);
        filterDef.setFilterClass(RestCsrfPreventionFilter.class.getCanonicalName());
        filterDef.addInitParameter(FILTER_INIT_PARAM, REMOVE_CUSTOMER + "," + ADD_CUSTOMER);
        context.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(FILTER_NAME);
        filterMap.addURLPatternDecoded(URI_CSRF_PROTECTED);
        context.addFilterMap(filterMap);

        SecurityCollection collection = new SecurityCollection();
        collection.addPatternDecoded(URI_PROTECTED);

        SecurityConstraint sc = new SecurityConstraint();
        sc.addAuthRole(ROLE);
        sc.addCollection(collection);
        context.addConstraint(sc);

        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod(METHOD);
        context.setLoginConfig(lc);

        AuthenticatorBase basicAuthenticator = new BasicAuthenticator();
        context.getPipeline().addValve(basicAuthenticator);
    }

    public static final class BasicCredentials {
        private final String method;
        private final String username;
        private final String password;
        private final String credentials;

        private BasicCredentials(String aMethod, String aUsername, String aPassword) {
            method = aMethod;
            username = aUsername;
            password = aPassword;
            String userCredentials = username + ":" + password;
            byte[] credentialsBytes = userCredentials.getBytes(StandardCharsets.ISO_8859_1);
            String base64auth = Base64.encodeBase64String(credentialsBytes);
            credentials = method + " " + base64auth;
        }

        private String getCredentials() {
            return credentials;
        }
    }

    public static class TesterServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            if (Objects.equals(LIST_CUSTOMERS, getRequestedPath(req))) {
                resp.getWriter().print(CUSTOMERS_LIST_RESPONSE);
            }
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            if (Objects.equals(REMOVE_CUSTOMER, getRequestedPath(req))) {
                resp.getWriter().print(CUSTOMER_REMOVED_RESPONSE);
            } else if (Objects.equals(ADD_CUSTOMER, getRequestedPath(req))) {
                resp.getWriter().print(CUSTOMER_ADDED_RESPONSE);
            }
        }

        private String getRequestedPath(HttpServletRequest request) {
            String path = request.getServletPath();
            if (Objects.nonNull(request.getPathInfo())) {
                path = path + request.getPathInfo();
            }
            return path;
        }
    }

    public static int getUrl(String path, ByteChunk out, Map<String, List<String>> reqHead,
            Map<String, List<String>> resHead) throws IOException {
        return methodUrl(path, out, 300_000, reqHead, resHead, "GET", true);
    }

    public static int methodUrl(String path, ByteChunk out, int readTimeout,
                Map<String, List<String>> reqHead, Map<String, List<String>> resHead, String method,
                boolean followRedirects) throws IOException {

        URL url = new URL(path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setUseCaches(false);
        connection.setReadTimeout(readTimeout);
        connection.setRequestMethod(method);
        connection.setInstanceFollowRedirects(followRedirects);
        if (reqHead != null) {
            for (Map.Entry<String, List<String>> entry : reqHead.entrySet()) {
                StringBuilder valueList = new StringBuilder();
                for (String value : entry.getValue()) {
                    if (valueList.length() > 0) {
                        valueList.append(',');
                    }
                    valueList.append(value);
                }
                connection.setRequestProperty(entry.getKey(),
                        valueList.toString());
            }
        }
        connection.connect();
        int rc = connection.getResponseCode();
        if (resHead != null) {
            // Skip the entry with null key that is used for the response line
            // that some Map implementations may not accept.
            for (Map.Entry<String, List<String>> entry : connection.getHeaderFields().entrySet()) {
                if (entry.getKey() != null) {
                    resHead.put(entry.getKey(), entry.getValue());
                }
            }
        }
        InputStream is;
        if (rc < 400) {
            is = connection.getInputStream();
        } else {
            is = connection.getErrorStream();
        }
        if (is != null) {
            try (BufferedInputStream bis = new BufferedInputStream(is)) {
                byte[] buf = new byte[2048];
                int rd = 0;
                while((rd = bis.read(buf)) > 0) {
                    out.append(buf, 0, rd);
                }
            }
        }
        return rc;
    }

    public static int postUrl(final byte[] body, String path, ByteChunk out,
            Map<String, List<String>> reqHead,
            Map<String, List<String>> resHead) throws IOException {
            BytesStreamer s = new BytesStreamer() {
            boolean done = false;
            @Override
            public byte[] next() {
                done = true;
                return body;

            }

            @Override
            public int getLength() {
                return body!=null?body.length:0;
            }

            @Override
            public int available() {
                if (done) {
                  return 0;
                } else {
                  return getLength();
                }
            }
        };
        return postUrl(false,s,path,out,reqHead,resHead);
    }


    public static int postUrl(boolean stream, BytesStreamer streamer, String path, ByteChunk out,
                Map<String, List<String>> reqHead,
                Map<String, List<String>> resHead) throws IOException {

        URL url = new URL(path);
        HttpURLConnection connection =
            (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setReadTimeout(1000000);
        if (reqHead != null) {
            for (Map.Entry<String, List<String>> entry : reqHead.entrySet()) {
                StringBuilder valueList = new StringBuilder();
                for (String value : entry.getValue()) {
                    if (valueList.length() > 0) {
                        valueList.append(',');
                    }
                    valueList.append(value);
                }
                connection.setRequestProperty(entry.getKey(),
                        valueList.toString());
            }
        }
        if (streamer != null && stream) {
            if (streamer.getLength()>0) {
                connection.setFixedLengthStreamingMode(streamer.getLength());
            } else {
                connection.setChunkedStreamingMode(1024);
            }
        }

        connection.connect();

        // Write the request body
        try (OutputStream os = connection.getOutputStream()) {
            while (streamer != null && streamer.available() > 0) {
                byte[] next = streamer.next();
                os.write(next);
                os.flush();
            }
        }

        int rc = connection.getResponseCode();
        if (resHead != null) {
            Map<String, List<String>> head = connection.getHeaderFields();
            resHead.putAll(head);
        }
        InputStream is;
        if (rc < 400) {
            is = connection.getInputStream();
        } else {
            is = connection.getErrorStream();
        }

        try (BufferedInputStream bis = new BufferedInputStream(is)) {
            byte[] buf = new byte[2048];
            int rd = 0;
            while((rd = bis.read(buf)) > 0) {
                out.append(buf, 0, rd);
            }
        }
        return rc;
    }
}