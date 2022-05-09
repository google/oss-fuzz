import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.io.entity.*;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.impl.bootstrap.RequesterBootstrap;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.impl.bootstrap.HttpRequester;
import org.apache.hc.core5.util.Timeout;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.net.URIAuthority;

import java.net.URI;
import java.net.URISyntaxException;
import java.lang.IllegalArgumentException;
import java.io.File;
import java.io.IOException;
import java.io.ByteArrayInputStream;

public class ClassicHttpRequestFuzzer {
    final static ContentType[] contentTypes = {
        ContentType.APPLICATION_ATOM_XML,
        ContentType.APPLICATION_FORM_URLENCODED,
        ContentType.APPLICATION_JSON,
        ContentType.APPLICATION_SVG_XML,
        ContentType.APPLICATION_XHTML_XML,
        ContentType.APPLICATION_XML,
        ContentType.IMAGE_BMP,
        ContentType.IMAGE_GIF,
        ContentType.IMAGE_JPEG,
        ContentType.IMAGE_PNG,
        ContentType.IMAGE_SVG,
        ContentType.IMAGE_TIFF,
        ContentType.IMAGE_WEBP,
        ContentType.MULTIPART_FORM_DATA,
        ContentType.TEXT_HTML,
        ContentType.TEXT_PLAIN,
        ContentType.TEXT_XML
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int entityChoice = data.consumeInt(0, 3);
        String name = data.consumeString(100);
        String value = data.consumeRemainingAsString();
        BasicClassicHttpRequest request;

        try {
            request = new BasicClassicHttpRequest(data.pickValue(Method.values()), value);
        } catch (IllegalArgumentException e) {
            return;
        }

        request.setVersion(data.pickValue(HttpVersion.ALL));
        request.addHeader(value, new Object());
        request.addHeader(new BasicHeader(name, value));
        request.setScheme(value);
        request.setAuthority(new URIAuthority(value, 8080));
        setRequestEntity(request, value, entityChoice, data.pickValue(contentTypes));
        
        request.getRequestUri();
        request.getPath();
        request.toString();
        request.getScheme();
        request.getEntity();
        request.getAuthority();
        try {
            request.getUri();
        } catch (URISyntaxException e) { }

        HttpRequester requester = RequesterBootstrap.bootstrap()
            .setSslContext(null)
            .setMaxTotal(2)
            .setDefaultMaxPerRoute(2)
            .create();

        final HttpHost target = new HttpHost(value, "localhost", 80);
        final HttpCoreContext context = HttpCoreContext.create();
        try {
            requester.execute(target, request, Timeout.ofSeconds(0), context);
        } catch (HttpException | IOException e) { }
    }

    public static void setRequestEntity(BasicClassicHttpRequest request, String value, int entityChoice, ContentType contentType) {
        ByteArrayInputStream stream = new ByteArrayInputStream(value.getBytes());
        switch (entityChoice) {
            case 0:
                request.setEntity(new StringEntity(value, contentType));
                break;
            case 1:
                request.setEntity(new InputStreamEntity(stream,contentType));
                break;
            case 2:
                request.setEntity(new BasicHttpEntity(stream, contentType));
                break;
            case 3:
                request.setEntity(new ByteArrayEntity(value.getBytes(), contentType));
                break;
        }
    }
}