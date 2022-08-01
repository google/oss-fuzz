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

import java.io.File;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.catalina.servlets.DefaultServlet;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;

public class Http11ProcessorDefaultServletFuzzer {
    static Tomcat tomcat = null;
    static Connector connector1 = null;
    static Context ctx = null;
    static String contextPath = null;
    static String baseDir = null;
    
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
        connector1.setPort(0);

        String docBase = new File(".").getAbsolutePath();

        ctx = tomcat.addContext("", docBase);

        Wrapper w = Tomcat.addServlet(ctx, "servlet", new DefaultServlet());
        ctx.addServletMappingDecoded("/", "servlet");

        try {
            tomcat.start();
        } catch (Exception e) {
            throw new FuzzerSecurityIssueHigh("Tomcat Start error!");
        }

    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // java.util.logging.Logger.getLogger("org.apache").setLevel(java.util.logging.Level.OFF);

        String str = data.consumeAsciiString(100);
        String str1 = data.consumeAsciiString(100);
        String str2 = data.consumeAsciiString(100);
        String str3 = data.consumeAsciiString(100);
        String str4 = data.consumeAsciiString(100);
        String str5 = data.consumeRemainingAsAsciiString();

        try {
            SocketAddress addr = new InetSocketAddress("localhost", tomcat.getConnector().getLocalPort());
            Socket socket = new Socket();
            socket.connect(addr, 0);
            OutputStream os = socket.getOutputStream();
            Writer writer = new OutputStreamWriter(os, "US-ASCII");
            InputStream is = socket.getInputStream();
            Reader r = new InputStreamReader(is, "US-ASCII");
            BufferedReader reader = new BufferedReader(r);

            // Write the headers
            writer.write("POST http://localhost:" + tomcat.getConnector().getLocalPort() +"/temp HTTP/1.1\r\n");
            writer.write("Host: localhost:" + tomcat.getConnector().getLocalPort() + "\r\n");
            writer.write("Transfer-Encoding: chunked\r\n");
            writer.write(str + "\r\n");
            writer.write(str1 + "\r\n");
            writer.write(str2 + "\r\n");
            writer.write("\r\n");
            writer.flush();

            // Write the request body
            writer.write(str3 + "\r\n");
            writer.write(str4 + "\r\n");
            writer.write(str5 + "\r\n");
            writer.write("\r\n");
            writer.flush();

            socket.close();
        } catch (IOException e) {
            throw new FuzzerSecurityIssueHigh("Should only throw IOException.");
        }
    }
}