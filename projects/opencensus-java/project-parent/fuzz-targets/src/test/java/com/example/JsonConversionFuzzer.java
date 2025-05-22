// Copyright 2023 Google LLC
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

package io.opencensus.exporter.trace.elasticsearch;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import io.opencensus.exporter.trace.elasticsearch.JsonConversionUtils;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.opencensus.common.Timestamp;
import io.opencensus.trace.Annotation;
import io.opencensus.trace.AttributeValue;
import io.opencensus.trace.Link;
import io.opencensus.trace.MessageEvent;
import io.opencensus.trace.MessageEvent.Type;
import io.opencensus.trace.SpanContext;
import io.opencensus.trace.SpanId;
import io.opencensus.trace.Status;
import io.opencensus.trace.TraceId;
import io.opencensus.trace.TraceOptions;
import io.opencensus.trace.Tracestate;
import io.opencensus.trace.export.SpanData;
import io.opencensus.trace.export.SpanData.Attributes;
import io.opencensus.trace.export.SpanData.Links;
import io.opencensus.trace.export.SpanData.TimedEvent;
import io.opencensus.trace.export.SpanData.TimedEvents;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class JsonConversionFuzzer {
    static List<SpanData> spanDataList;

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        spanDataList = new ArrayList<SpanData>();

        String name = data.consumeString(200);
        String traceId = data.consumeString(200);
        String spanId = data.consumeString(200);
        String parentSpanId = data.consumeString(200);
        String spanName = data.consumeString(200);
		String key = data.consumeString(200);
		String value = data.consumeString(200);
        boolean isSampled = data.consumeBoolean();
        boolean hasRemoteParent = data.consumeBoolean();

		try {
			List<TimedEvent<MessageEvent>> messageEvents =
            ImmutableList.of(
                TimedEvent.create(
                    Timestamp.create(data.consumeInt(), data.consumeInt()),
                    MessageEvent.builder(Type.RECEIVED, 0).setCompressedMessageSize(data.consumeInt()).build()),
                TimedEvent.create(
                    Timestamp.create(data.consumeInt(), data.consumeInt()),
                    MessageEvent.builder(Type.SENT, 0).setCompressedMessageSize(data.consumeInt()).build()));

			SpanData spanData =
                SpanData.create(
                    SpanContext.create(
                        TraceId.fromLowerBase16(traceId),
                        SpanId.fromLowerBase16(spanId),
                        TraceOptions.builder().setIsSampled(isSampled).build(),
                        Tracestate.builder().build()),
                    SpanId.fromLowerBase16(parentSpanId),
                    hasRemoteParent,
                    spanName,
                    null,
                    Timestamp.create(data.consumeInt(), data.consumeInt()),
                    Attributes.create(ImmutableMap.of(key, AttributeValue.stringAttributeValue(value)), 0),
                    TimedEvents.create(Collections.emptyList(), 0),
                    TimedEvents.create(messageEvents, 0),
                    Links.create(Collections.<Link>emptyList(), 0),
                    null,
                    Status.OK,
                    Timestamp.create(data.consumeInt(), data.consumeInt()));

			spanDataList.add(spanData);
        	List<String> json = JsonConversionUtils.convertToJson(name, spanDataList);
		} catch (IllegalArgumentException e) {
		}
    }
}
