import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import jakarta.servlet.http.Cookie;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import java.util.Locale;

import static org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE_REQUEST_ATTRIBUTE_NAME;

public class CookieLocaleResolverFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		CookieLocaleResolver resolver = new CookieLocaleResolver();
		String cookieName = data.consumeString(100);
		if (cookieName.isEmpty()) {
			return;
		}

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("http");
		request.setServerName("localhost");
		request.setServerPort(data.consumeInt());
		request.setRequestURI(data.consumeString(100));
		request.setQueryString(data.consumeString(100));
		request.removeAttribute(LOCALE_REQUEST_ATTRIBUTE_NAME);


		MockHttpServletResponse response = new MockHttpServletResponse();
		if (data.consumeBoolean()) {
			try {
				response.setHeader(data.consumeString(50), data.consumeString(100));
			} catch (IllegalArgumentException ignored) {}
		}

		try {
			if (data.consumeBoolean()) {
				Locale locale = new Locale(data.consumeString(50));
				resolver.setLocale(request, response, locale);
			}

			Cookie cookie = new Cookie(data.consumeString(100), data.consumeString(500));
			request.setCookies(cookie);
			resolver.resolveLocaleContext(request);

		} catch (IllegalArgumentException | IllegalStateException ignored) {}
	}
}
