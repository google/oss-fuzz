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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import java.io.OutputStreamWriter;
import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.net.URL;
import java.net.HttpURLConnection;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.buf.ByteChunk;

public class ConnectorSendFileFuzzer {
    static Tomcat tomcat = null;
    static Connector connector1 = null;
    static int PORT = 8088;
    static Context root = null;
    static String contextPath = null;
    static String baseDir = null;
    static int counter = Integer.MIN_VALUE;
    static int EXPECTED_CONTENT_LENGTH = 100000;
    static String [] encodings = {
        "US-ASCII",
        "ISO-8859-1",
        "UTF-8",
        "UTF-16BE",
        "UTF-16LE",
        "UTF-16"
    };
    static String [] content_type = {
        "application/java-archive", 
        "application/EDI-X12", 
        "application/EDIFACT",    
        "application/javascript",   
        "application/octet-stream",   
        "application/ogg",   
        "application/pdf",  
        "application/xhtml+xml",   
        "application/x-shockwave-flash",    
        "application/json",  
        "application/ld+json",  
        "application/xml",   
        "application/zip",  
        "application/x-www-form-urlencoded",

        "audio/mpeg",   
        "audio/x-ms-wma",   
        "audio/vnd.rn-realaudio",   
        "audio/x-wav",

        "image/gif",   
        "image/jpeg",   
        "image/png",   
        "image/tiff",    
        "image/vnd.microsoft.icon",    
        "image/x-icon",   
        "image/vnd.djvu",   
        "image/svg+xml",

        "multipart/mixed",    
        "multipart/alternative",   
        "multipart/related",  
        "multipart/form-data",

        "text/css",    
        "text/csv",    
        "text/html",    
        "text/javascript",    
        "text/plain",    
        "text/xml",

        "video/mpeg",    
        "video/mp4",    
        "video/quicktime",    
        "video/x-ms-wmv",    
        "video/x-msvideo",    
        "video/x-flv",   
        "video/webm",

        "application/vnd.android.package-archive",
        "application/vnd.oasis.opendocument.text",    
        "application/vnd.oasis.opendocument.spreadsheet",  
        "application/vnd.oasis.opendocument.presentation",   
        "application/vnd.oasis.opendocument.graphics",   
        "application/vnd.ms-excel",    
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",   
        "application/vnd.ms-powerpoint",    
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",    
        "application/msword",   
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",   
        "application/vnd.mozilla.xul+xml",
    };

    public static void fuzzerTearDown() {

        try {
            tomcat.stop();
            tomcat.destroy();
            tomcat = null;
            System.gc();
        } catch (Exception e) {
            throw new FuzzerSecurityIssueHigh("Teardown Error!");
        }
    }
    
    public static void fuzzerInitialize() {
        tomcat = new Tomcat();

        baseDir = "temp";

        tomcat.setBaseDir(baseDir);

        connector1 = tomcat.getConnector();
        // connector1.setPort(PORT);
        connector1.setPort(0);

        String docBase = new File(".").getAbsolutePath();

        root = tomcat.addContext("", docBase);

        try {
            tomcat.start();
        } catch (Exception e) {
            throw new FuzzerSecurityIssueHigh("Tomcat Start error!");
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // java.util.logging.Logger.getLogger("org.apache").setLevel(java.util.logging.Level.OFF);

        int c_num = data.consumeInt(0, content_type.length - 1);
        int e_num = data.consumeInt(0, encodings.length - 1);
        byte [] ba = data.consumeBytes(8192);
        File file = null;

        try {
            file = generateFile(new File("./" + baseDir), ba);
        } catch (Exception e) {
            throw new FuzzerSecurityIssueHigh("generateFile Error!");
        }

        if (counter < Integer.MAX_VALUE) {
            counter++;   
        }
        else {
            System.exit(1);
            // throw new FuzzerSecurityIssueHigh("Max Counter Reached!");
        }

        WritingServlet servlet = new WritingServlet(file, c_num, e_num);
        Tomcat.addServlet(root, "servlet" + "-" + counter, servlet);
        root.addServletMappingDecoded("/servlet", "servlet" + "-" + counter);

        ByteChunk bc = new ByteChunk();
        Map<String, List<String>> respHeaders = new HashMap<>();
        int rc = -1;
        try {
            rc = getUrl("http://localhost:" + tomcat.getConnector().getLocalPort() + "/servlet", bc, null, respHeaders);   
        } catch (Exception e) {
            throw new FuzzerSecurityIssueHigh("getUrl error!");
        }
        assert rc == HttpServletResponse.SC_OK : new FuzzerSecurityIssueHigh("rc is not ok!");

        bc.recycle();
        respHeaders.clear();

        file.delete();

        try {
            System.gc();
        } catch (Exception e) {
            throw new FuzzerSecurityIssueHigh("gc Error!");
        }
        
    }

    public static class WritingServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final File f;
        private final int c;
        private final int e;

        public WritingServlet(File f, int c, int e) {
            this.f = f;
            this.c = c;
            this.e = e;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType(content_type[c]);
            resp.setCharacterEncoding(encodings[e]);
            resp.setContentLengthLong(f.length());

            req.setAttribute(Globals.SENDFILE_FILENAME_ATTR, f.getAbsolutePath());
            req.setAttribute(Globals.SENDFILE_FILE_START_ATTR, Long.valueOf(0));
            req.setAttribute(Globals.SENDFILE_FILE_END_ATTR, Long.valueOf(f.length()));

            byte[] c = new byte[8192];
                try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(f))) {
                    int len = 0;
                    int written = 0;
                    long start = System.currentTimeMillis();
                    do {
                        len = in.read(c);
                        if (len > 0) {
                            resp.getOutputStream().write(c, 0, len);
                            written += len;
                        }
                    } while (len > 0);
                    // System.out.println("Server Wrote " + written + " bytes in " + (System.currentTimeMillis() - start) + " ms.");
                }
        }
    }

    public static File generateFile(File dir, byte [] ba) throws IOException {
        String name = "testSendFile-"; // + System.currentTimeMillis() + suffix; // + ".txt";
        String suffix = "";
        // File f = new File(dir, name);
        File f = File.createTempFile(name, suffix, dir);
        
        // try (FileWriter fw = new FileWriter(f, false); BufferedWriter w = new BufferedWriter(fw)) {
        try (FileOutputStream w = new FileOutputStream(f)) {
            w.write(ba);
            w.flush();
        }
        // System.out.println("Created file:" + f.getAbsolutePath() + " with " + f.length() + " bytes.");
        return f;

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
}