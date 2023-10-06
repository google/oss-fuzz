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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.context.ApplicationContext;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.i18n.LocaleContext;
import org.springframework.context.i18n.SimpleLocaleContext;
import org.springframework.http.codec.multipart.Part;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.result.view.BindStatus;
import org.springframework.web.reactive.result.view.RequestContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.beans.NotReadablePropertyException;
import java.security.Principal;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import reactor.core.publisher.Mono;
import org.springframework.beans.InvalidPropertyException;

public class BindStatusFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		MockHttpServletRequest request = new MockHttpServletRequest("", "");
		Map<String, Object> objectMap = new HashMap<String, Object>();

		for (int i = 0; i < data.consumeInt(0, 200); i++) {
			String name = data.consumeString(50);
			switch (data.consumeInt(0, 3)) {
				case 0 -> objectMap.put(name, data.consumeString(50));
				case 1 -> objectMap.put(name, data.consumeInt());
				case 2 -> objectMap.put(name, data.consumeBytes(100));
				case 3 -> objectMap.put(name, data.consumeBoolean());
			}
		}

		RequestContext context = new RequestContext(new DummyWebExchange(), objectMap, new DummyMessage());
		try {
			BindStatus bindStatus = new BindStatus(context, data.consumeString(100), data.consumeBoolean());
			bindStatus.getActualValue();
			bindStatus.getEditor();
			bindStatus.getDisplayValue();
			bindStatus.getErrors();
			bindStatus.getErrorMessages();
			bindStatus.getPath();
		} catch (IllegalStateException | InvalidPropertyException e) {}
	}

	// Mocked classes
	public static class DummyMessage implements MessageSource {

		@Override
		public String getMessage(String code, Object[] args, String defaultMessage, Locale locale) {
			return null;
		}

		@Override
		public String getMessage(String code, Object[] args, Locale locale) throws NoSuchMessageException {
			return null;
		}

		@Override
		public String getMessage(MessageSourceResolvable resolvable, Locale locale) throws NoSuchMessageException {
			return null;
		}
	}


	public static class DummyWebExchange implements ServerWebExchange {

		@Override
		public ServerHttpRequest getRequest() {
			return null;
		}

		@Override
		public ServerHttpResponse getResponse() {
			return null;
		}

		@Override
		public Map<String, Object> getAttributes() {
			return new HashMap<String, Object>() {{
				put("foo", "bar");
			}};
		}

		@Override
		public Mono<WebSession> getSession() {
			return null;
		}

		@Override
		public <T extends Principal> Mono<T> getPrincipal() {
			return null;
		}

		@Override
		public Mono<MultiValueMap<String, String>> getFormData() {
			return null;
		}

		@Override
		public Mono<MultiValueMap<String, Part>> getMultipartData() {
			return null;
		}

		@Override
		public LocaleContext getLocaleContext() {
			return new SimpleLocaleContext(new Locale("EN_us"));
		}

		@Override
		public ApplicationContext getApplicationContext() {
			return null;
		}

		@Override
		public boolean isNotModified() {
			return false;
		}

		@Override
		public boolean checkNotModified(Instant lastModified) {
			return false;
		}

		@Override
		public boolean checkNotModified(String etag) {
			return false;
		}

		@Override
		public boolean checkNotModified(String etag, Instant lastModified) {
			return false;
		}

		@Override
		public String transformUrl(String url) {
			return null;
		}

		@Override
		public void addUrlTransformer(Function<String, String> transformer) {

		}

		@Override
		public String getLogPrefix() {
			return null;
		}
	}
}
