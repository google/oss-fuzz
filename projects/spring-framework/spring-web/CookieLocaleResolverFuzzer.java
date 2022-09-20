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
