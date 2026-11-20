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

import fuzz.axis2.services.FuzzService;
import jakarta.servlet.ServletContext;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.description.TransportInDescription;
import org.apache.axis2.description.TransportOutDescription;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.MessageReceiver;
import org.apache.axis2.kernel.OutTransportInfo;
import org.apache.axis2.kernel.RequestResponseTransport;
import org.apache.axis2.transport.http.AxisServlet;
import org.apache.axis2.transport.http.HTTPWorker;
import org.apache.axis2.transport.http.server.AxisHttpRequest;
import org.apache.axis2.transport.http.server.AxisHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;

import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Test deployment for the request-pipeline fuzzers.
 * Builds a ConfigurationContext from a generated axis2.xml, deploys the fuzz services and
 * initialises a real AxisServlet over it. Requests are then delivered with
 * {@link #servlet(MockHttp.Req)} (the servlet transport, as in Tomcat/Jetty) or
 * {@link #standalone(MockHttp.Req)} (HTTPWorker, the SimpleHTTPServer transport).
 */
public final class Env {

    // Canaries: strings that must never reach an anonymous caller.
    public static final String HIDDEN_NS = "http://hidden.canary/Q7x9";
    public static final String HIDDEN_DOC = "HIDDEN_DOC_CANARY_3b7";
    public static final String SERVICES_XML_CANARY = "SERVICES_XML_CANARY_91c";
    public static final String METAINF_PROPS_CANARY = "METAINF_PROPS_CANARY_d21";
    public static final String OUTSIDE_CANARY = "OUTSIDE_CANARY_44d";
    public static final String ROOTFILE_CANARY = "ROOTFILE_CANARY_e02";
    public static final String PARENT_CANARY = "PARENT_CANARY_7aa";
    public static final String[] ALL_CANARIES = {HIDDEN_NS, HIDDEN_DOC, SERVICES_XML_CANARY,
            METAINF_PROPS_CANARY, OUTSIDE_CANARY, ROOTFILE_CANARY, PARENT_CANARY};
    /** Everything except the hidden namespace, which an invoked Hidden operation may echo. */
    public static final String[] STRICT_CANARIES = {HIDDEN_DOC, SERVICES_XML_CANARY,
            METAINF_PROPS_CANARY, OUTSIDE_CANARY, ROOTFILE_CANARY, PARENT_CANARY};

    /** axis2.xml variant. */
    public static final class Config {
        final String name;
        final Map<String, String> params = new LinkedHashMap<>();
        String receivers =
                "        <messageReceiver mep=\"http://www.w3.org/ns/wsdl/in-only\" class=\"org.apache.axis2.rpc.receivers.RPCInOnlyMessageReceiver\"/>\n"
              + "        <messageReceiver mep=\"http://www.w3.org/ns/wsdl/in-out\" class=\"org.apache.axis2.rpc.receivers.RPCMessageReceiver\"/>\n"
              + "        <messageReceiver mep=\"http://www.w3.org/ns/wsdl/robust-in-only\" class=\"org.apache.axis2.rpc.receivers.RPCInOnlyMessageReceiver\"/>";
        String builders = "";
        String formatters = "";
        String transportHandlers = "";
        String dispatchHandlers = "";
        String modules = "    <module ref=\"addressing\"/>";

        public Config(String name) {
            this.name = name;
        }

        public Config param(String k, String v) {
            params.put(k, v);
            return this;
        }

        public Config builder(String contentType, String cls) {
            builders += "        <messageBuilder contentType=\"" + contentType + "\" class=\"" + cls + "\"/>\n";
            return this;
        }

        public Config formatter(String contentType, String cls) {
            formatters += "        <messageFormatter contentType=\"" + contentType + "\" class=\"" + cls + "\"/>\n";
            return this;
        }

        public Config transportHandler(String name, String cls) {
            transportHandlers += "            <handler name=\"" + name + "\" class=\"" + cls
                    + "\">\n                <order phase=\"Transport\"/>\n            </handler>\n";
            return this;
        }

        public Config dispatchHandler(String name, String cls) {
            dispatchHandlers += "            <handler name=\"" + name + "\" class=\"" + cls + "\"/>\n";
            return this;
        }

        String render() throws Exception {
            String t;
            try (InputStream in = Env.class.getResourceAsStream("/fuzz/axis2/axis2-template.xml")) {
                t = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            StringBuilder p = new StringBuilder();
            for (Map.Entry<String, String> e : params.entrySet()) {
                p.append("    <parameter name=\"").append(e.getKey()).append("\">")
                        .append(e.getValue()).append("</parameter>\n");
            }
            return t.replace("@PARAMS@", p).replace("@RECEIVERS@", receivers)
                    .replace("@BUILDERS@", builders).replace("@FORMATTERS@", formatters)
                    .replace("@TRANSPORT_HANDLERS@", transportHandlers)
                    .replace("@DISPATCH_HANDLERS@", dispatchHandlers).replace("@MODULES@", modules);
        }
    }

    public final ConfigurationContext configContext;
    public final AxisConfiguration axisConfig;
    public final AxisServlet servlet;
    private final ServletContext servletContext;
    public final Path repo;

    private Env(ConfigurationContext cc, AxisServlet servlet, ServletContext sc, Path repo) {
        this.configContext = cc;
        this.axisConfig = cc.getAxisConfiguration();
        this.servlet = servlet;
        this.servletContext = sc;
        this.repo = repo;
    }

    /** Creates the context. Services are added by the caller before {@link #start}. */
    public static ConfigurationContext context(Config cfg, Path work) throws Exception {
        Path repo = work.resolve("repo-" + cfg.name);
        Files.createDirectories(repo.resolve("modules"));
        Files.createDirectories(repo.resolve("services"));
        Path axis2xml = repo.resolve("axis2.xml");
        Files.writeString(axis2xml, cfg.render());
        // addressing.mar is packaged into the fuzzer jar by the pom (maven-dependency-plugin)
        try (InputStream mar = Env.class.getResourceAsStream("/fuzz/axis2/addressing.mar")) {
            if (mar == null) {
                throw new IllegalStateException("addressing.mar is missing from the fuzzer jar");
            }
            Files.copy(mar, repo.resolve("modules/addressing.mar"), StandardCopyOption.REPLACE_EXISTING);
        }
        return ConfigurationContextFactory.createConfigurationContextFromFileSystem(
                repo.toString(), axis2xml.toString());
    }

    public static Env start(ConfigurationContext cc, Path work, String cfgName) throws Exception {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put(AxisServlet.CONFIGURATION_CONTEXT, cc);
        ServletContext sc = MockHttp.servletContext(attrs, work.resolve("webroot").toString());
        AxisServlet servlet = new AxisServlet();
        servlet.init(MockHttp.servletConfig(sc));
        return new Env(cc, servlet, sc, work.resolve("repo-" + cfgName));
    }

    // ------------------------------------------------------------------ service deployment

    /** Fresh scratch directory for one harness (repos, packaged META-INF files). */
    public static Path workDir(String harness) throws java.io.IOException {
        Path p = Files.createTempDirectory("axis2-" + harness + "-");
        p.toFile().deleteOnExit();
        return p;
    }

    public static AxisService pojo(AxisConfiguration ac, Class<?> impl, String name) throws AxisFault {
        AxisService s = AxisService.createService(impl.getName(), ac);
        s.setName(name);
        return s;
    }

    public static AxisService pojo(AxisConfiguration ac, Class<?> impl, String name,
                                   Map<String, MessageReceiver> receivers) throws AxisFault {
        AxisService s = AxisService.createService(impl.getName(), ac, receivers,
                "http://services.axis2.fuzz", "http://services.axis2.fuzz/xsd",
                Env.class.getClassLoader());
        s.setName(name);
        return s;
    }

    /**
     * The standard SOAP/REST deployment used by the pipeline, body-limit and dispatch harnesses:
     *  FuzzService - ordinary service
     *  Secret      - same implementation; treated as protected by a container URL constraint
     *  Hidden      - exposeServiceMetadata=false, canary namespace/documentation
     *  Meta        - packaged META-INF documents behind a URLClassLoader, canaries around them
     */
    public static void deployStandard(AxisConfiguration ac, Path work) throws Exception {
        ac.addService(pojo(ac, FuzzService.class, "FuzzService"));
        ac.addService(pojo(ac, FuzzService.class, "Secret"));

        AxisService hidden = pojo(ac, FuzzService.class, "Hidden");
        hidden.addParameter(new Parameter("exposeServiceMetadata", "false"));
        hidden.setTargetNamespace(HIDDEN_NS);
        hidden.setDocumentation(HIDDEN_DOC);
        ac.addService(hidden);

        AxisService meta = pojo(ac, FuzzService.class, "Meta");
        meta.setClassLoader(metaLoader(work));
        ac.addService(meta);
    }

    /**
     * Layout (all under work/meta):
     *   parent/META-INF/parentonly.xsd   - in the PARENT loader: must not be served (AXIS2-5846)
     *   outside.xsd                      - sibling of the archive root: traversal target
     *   aar/outside2.xsd                 - archive root but not META-INF: must not be served
     *   aar/META-INF/services.xml        - must not be served
     *   aar/META-INF/keystore.properties - must not be served
     *   aar/META-INF/types.xsd, sub/inner.xsd, svc.wsdl - legitimately servable
     */
    static ClassLoader metaLoader(Path work) throws Exception {
        Path base = work.resolve("meta");
        Path parent = base.resolve("parent");
        Path aar = base.resolve("aar");
        Files.createDirectories(parent.resolve("META-INF"));
        Files.createDirectories(aar.resolve("META-INF/sub"));
        String xsd = "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:t\">"
                + "<xs:element name=\"e\" type=\"xs:string\"/></xs:schema>";
        Files.writeString(parent.resolve("META-INF/parentonly.xsd"), "<!-- " + PARENT_CANARY + " -->" + xsd);
        Files.writeString(base.resolve("outside.xsd"), "<!-- " + OUTSIDE_CANARY + " -->" + xsd);
        Files.writeString(aar.resolve("outside2.xsd"), "<!-- " + ROOTFILE_CANARY + " -->" + xsd);
        Files.writeString(aar.resolve("META-INF/services.xml"),
                "<service name=\"Meta\"><parameter name=\"pw\">" + SERVICES_XML_CANARY + "</parameter></service>");
        Files.writeString(aar.resolve("META-INF/keystore.properties"), "password=" + METAINF_PROPS_CANARY);
        Files.writeString(aar.resolve("META-INF/types.xsd"), xsd);
        Files.writeString(aar.resolve("META-INF/sub/inner.xsd"), xsd);
        Files.writeString(aar.resolve("META-INF/svc.wsdl"),
                "<definitions xmlns=\"http://schemas.xmlsoap.org/wsdl/\" targetNamespace=\"urn:w\"/>");
        URLClassLoader parentLoader = new URLClassLoader(new URL[] {parent.toUri().toURL()},
                Env.class.getClassLoader());
        return new URLClassLoader(new URL[] {aar.toUri().toURL()}, parentLoader);
    }

    /**
     * Sends representative requests before fuzzing starts (oracles inactive), so lazy
     * initialisation is not charged to the first fuzz input.
     */
    public void warmup() {
        String[] reqs = {
            "GET /axis2/services/FuzzService?wsdl HTTP/1.1\n\n",
            "GET /axis2/services/FuzzService?xsd HTTP/1.1\n\n",
            "GET /axis2/services/FuzzService?wsdl2 HTTP/1.1\n\n",
            "GET /axis2/services/FuzzService/echo?args0=x HTTP/1.1\n\n",
            "POST /axis2/services/FuzzService HTTP/1.1\nContent-Type: text/xml; charset=UTF-8\nSOAPAction: urn:echo\n\n"
                + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>"
                + "<ns:echo xmlns:ns=\"http://services.axis2.fuzz\"><ns:args0>x</ns:args0></ns:echo>"
                + "</soapenv:Body></soapenv:Envelope>",
            "POST /axis2/services/FuzzService/echo HTTP/1.1\nContent-Type: application/xml\n\n"
                + "<ns:echo xmlns:ns=\"http://services.axis2.fuzz\"><ns:args0>x</ns:args0></ns:echo>",
            "POST /axis2/services/JsonService/echo HTTP/1.1\nContent-Type: application/json\n\n"
                + "{\"echo\":[{\"arg0\":\"x\"}]}",
            "POST /axis2/services/FuzzService/echo HTTP/1.1\nContent-Type: application/json\n\n"
                + "{\"echo\":{\"args0\":\"x\"}}",
        };
        for (int round = 0; round < 3; round++) {
            for (String r : reqs) {
                HttpInput in = HttpInput.parse(r.getBytes(StandardCharsets.UTF_8), 1 << 20);
                try {
                    servlet(in.req);
                } catch (Throwable ignored) {
                    // warm-up only
                }
                in = HttpInput.parse(r.getBytes(StandardCharsets.UTF_8), 1 << 20);
                try {
                    standalone(in.req);
                } catch (Throwable ignored) {
                    // warm-up only
                }
            }
        }
        fuzz.axis2.services.Invoked.take();
    }

    // ------------------------------------------------------------------ request delivery

    /** Delivers a request through AxisServlet.service(), the servlet-container transport. */
    public MockHttp.Exchange servlet(MockHttp.Req req) throws Exception {
        MockHttp.Exchange ex = MockHttp.exchange(req, servletContext);
        try {
            servlet.service(ex.request, ex.response);
        } finally {
            ex.response.flushBuffer(); // a container flushes getWriter() output at the end
        }
        return ex;
    }

    /** Delivers a request through HTTPWorker, the standalone SimpleHTTPServer transport. */
    public MockHttp.Exchange standalone(MockHttp.Req req) throws Exception {
        MockHttp.Exchange ex = MockHttp.exchange(req, servletContext);
        String uri = req.rawUri + (req.query != null ? "?" + req.query : "");
        List<Header> hdrs = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : req.headers.entrySet()) {
            for (String v : e.getValue()) {
                hdrs.add(new BasicHeader(e.getKey(), v));
            }
        }
        InvocationHandler rh = (p, m, a) -> {
            switch (m.getName()) {
                case "getMethod": return req.method;
                case "getRequestURI": return uri;
                case "getContentType": return req.first("Content-Type");
                case "getInputStream": return ex.input;
                case "headerIterator": {
                    if (a == null || a.length == 0) return hdrs.iterator();
                    List<Header> sel = new ArrayList<>();
                    for (Header h : hdrs) if (h.getName().equalsIgnoreCase((String) a[0])) sel.add(h);
                    return sel.iterator();
                }
                case "getHeaders": {
                    if (a == null || a.length == 0) return hdrs.toArray(new Header[0]);
                    List<Header> sel = new ArrayList<>();
                    for (Header h : hdrs) if (h.getName().equalsIgnoreCase((String) a[0])) sel.add(h);
                    return sel.toArray(new Header[0]);
                }
                case "getFirstHeader":
                case "getHeader": {
                    for (Header h : hdrs) if (h.getName().equalsIgnoreCase((String) a[0])) return h;
                    return null;
                }
                case "getLastHeader": {
                    Header last = null;
                    for (Header h : hdrs) if (h.getName().equalsIgnoreCase((String) a[0])) last = h;
                    return last;
                }
                case "containsHeader": {
                    for (Header h : hdrs) if (h.getName().equalsIgnoreCase((String) a[0])) return true;
                    return false;
                }
                case "countHeaders": {
                    int c = 0;
                    for (Header h : hdrs) if (h.getName().equalsIgnoreCase((String) a[0])) c++;
                    return c;
                }
                case "hashCode": return System.identityHashCode(p);
                case "equals": return p == a[0];
                case "toString": return "MockAxisHttpRequest";
                default: return MockHttp.defaultValue(m);
            }
        };
        AxisHttpRequest request = (AxisHttpRequest) Proxy.newProxyInstance(Env.class.getClassLoader(),
                new Class<?>[] {AxisHttpRequest.class}, rh);
        MockHttp.Resp resp = ex.resp;
        InvocationHandler sh = (p, m, a) -> {
            switch (m.getName()) {
                case "getOutputStream": return ex.response.getOutputStream();
                case "setStatus": resp.status = (Integer) a[0]; return null;
                case "sendError": resp.status = (Integer) a[0];
                    if (a.length > 1 && a[1] != null) ex.response.getOutputStream().write(((String) a[1]).getBytes(StandardCharsets.UTF_8));
                    return null;
                case "setContentType": resp.contentType = (String) a[0]; return null;
                case "addHeader":
                case "setHeader": {
                    if (a.length == 1 && a[0] instanceof Header) {
                        Header h = (Header) a[0];
                        resp.headers.computeIfAbsent(h.getName(), k -> new ArrayList<>()).add(h.getValue());
                    } else if (a.length == 2) {
                        resp.headers.computeIfAbsent(String.valueOf(a[0]), k -> new ArrayList<>()).add(String.valueOf(a[1]));
                    }
                    return null;
                }
                case "hashCode": return System.identityHashCode(p);
                case "equals": return p == a[0];
                case "toString": return "MockAxisHttpResponse";
                default: return MockHttp.defaultValue(m);
            }
        };
        AxisHttpResponse response = (AxisHttpResponse) Proxy.newProxyInstance(Env.class.getClassLoader(),
                new Class<?>[] {AxisHttpResponse.class, OutTransportInfo.class}, sh);

        // Mirrors AxisHttpService.handleRequest/doService.
        MessageContext mc = configContext.createMessageContext();
        mc.setIncomingTransportName(Constants.TRANSPORT_HTTP);
        mc.setProperty(MessageContext.REMOTE_ADDR, "127.0.0.1");
        TransportOutDescription tout = axisConfig.getTransportOut(Constants.TRANSPORT_HTTP);
        TransportInDescription tin = axisConfig.getTransportIn(Constants.TRANSPORT_HTTP);
        mc.setTransportIn(tin);
        mc.setTransportOut(tout);
        mc.setServerSide(true);
        mc.setProperty(Constants.Configuration.TRANSPORT_IN_URL, uri);
        Map<String, String> headerMap = new HashMap<>();
        for (Header h : hdrs) {
            headerMap.put(h.getName(), h.getValue());
        }
        mc.setProperty(MessageContext.TRANSPORT_HEADERS, headerMap);
        mc.setProperty(Constants.Configuration.CONTENT_TYPE, req.first("Content-Type"));
        mc.setProperty(MessageContext.TRANSPORT_OUT, ex.response.getOutputStream());
        mc.setProperty(Constants.OUT_TRANSPORT_INFO, response);
        mc.setTo(new EndpointReference(uri));
        mc.setProperty(RequestResponseTransport.TRANSPORT_CONTROL, new SimpleRRT());
        try {
            new HTTPWorker().service(request, response, mc);
        } catch (AxisFault f) {
            // AxisHttpService turns this into a fault response; the oracles only need the body
            resp.status = 500;
        }
        return ex;
    }

    static final class SimpleRRT implements RequestResponseTransport {
        private RequestResponseTransportStatus status = RequestResponseTransportStatus.WAITING;
        private boolean written;

        public void acknowledgeMessage(MessageContext msgContext) {
            status = RequestResponseTransportStatus.ACKED;
        }

        public void awaitResponse() {
            // single-threaded harness: nothing to wait for
        }

        public void signalResponseReady() {
            status = RequestResponseTransportStatus.SIGNALLED;
        }

        public RequestResponseTransportStatus getStatus() {
            return status;
        }

        public void signalFaultReady(AxisFault fault) {
            status = RequestResponseTransportStatus.SIGNALLED;
        }

        public boolean isResponseWritten() {
            return written;
        }

        public void setResponseWritten(boolean responseWritten) {
            written = responseWritten;
        }
    }
}
