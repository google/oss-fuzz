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
        try{
            start();

            var client = HttpClient.newHttpClient();
            URI uri = new URI("http://localhost:6060/axis2/services/StockQuoteService/" + fuzzedDataProvider.consumeRemainingAsString());
            var request = HttpRequest.newBuilder(uri)
                        .GET()
                        .build();
            var reponse = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (MalformedURLException e) {
            
        } catch (IOException e) {

        } catch (URISyntaxException e) {

        } catch (InterruptedException e) {

        }

        try {
            stop();
        } catch (Exception ex) {

        }


    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        HttpInterfaceFuzzer fixture = new HttpInterfaceFuzzer(fuzzedDataProvider);
        fixture.test();

        fixture = null;
        Thread.sleep(100); // good old way to get sockets closed.
    }
}