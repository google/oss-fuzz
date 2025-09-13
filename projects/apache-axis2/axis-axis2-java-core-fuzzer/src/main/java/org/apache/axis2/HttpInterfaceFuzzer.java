package org.apache.axis2;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import org.apache.http.client.utils.URIBuilder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.apache.axis2.kernel.SimpleAxis2Server;

public class HttpInterfaceFuzzer extends SimpleAxis2Server {

    private FuzzedDataProvider fuzzedDataProvider;

    public HttpInterfaceFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        super(null, null);
        this.fuzzedDataProvider = fuzzedDataProvider;

        deployService("samples.quickstart.service.pojo.StockQuoteService");
    }

    void test() {
        // Begin cleanup
        try {
            stop();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        try {
            start();

            var client = HttpClient.newHttpClient();
            String host = "localhost";
            int port = getPort(); // Get the dynamically assigned port
            URI uri = new URI("http://" + host + ":" + port + "/axis2/services/StockQuoteService/" + fuzzedDataProvider.consumeRemainingAsString());
            var request = HttpRequest.newBuilder(uri)
                        .GET()
                        .build();
            var reponse = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                stop();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        HttpInterfaceFuzzer fixture = new HttpInterfaceFuzzer(fuzzedDataProvider);
        fixture.test();

        fixture = null;
        Thread.sleep(100); // Ensure closed state ready for next instance
    }

    private int getPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            e.printStackTrace();
            return 6060; // Backup in failure of auto assign
        }
    }
}