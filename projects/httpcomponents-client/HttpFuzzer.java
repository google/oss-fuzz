import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.ArrayList;
import java.util.List;
import java.net.URI;
import java.io.IOException;

import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.auth.CredentialsProviderBuilder;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;

public class HttpFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		final CredentialsProvider credsProvider = CredentialsProviderBuilder.create()
			.add(new AuthScope(data.consumeRemainingAsString(), data.consumeInt()), data.consumeRemainingAsString(), data.consumeRemainingAsString().toCharArray())
			.build();

		final CloseableHttpClient httpClient = HttpClients.custom()
			.setDefaultCredentialsProvider(credsProvider)
			.build();
		
		HttpPost httpPost = new HttpPost("http://localhost");
		List<NameValuePair> nvps = new ArrayList<>();
		nvps.add(new BasicNameValuePair(data.consumeRemainingAsString(), data.consumeRemainingAsString()));

		httpPost.setEntity(new UrlEncodedFormEntity(nvps));

		try {
			httpClient.execute(httpPost);
		} catch (IOException e) { }
	}
}