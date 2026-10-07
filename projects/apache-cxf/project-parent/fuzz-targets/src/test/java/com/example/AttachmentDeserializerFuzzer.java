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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import java.io.*;
import java.util.Collection;
import java.util.Iterator;

import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.cxf.message.Attachment;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.ExchangeImpl;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.attachment.AttachmentDeserializer;
import org.apache.cxf.attachment.HeaderSizeExceededException;

public class AttachmentDeserializerFuzzer {
    static MessageImpl msg;
    
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        msg = new MessageImpl();
        Exchange exchange = new ExchangeImpl();
        msg.setExchange(exchange);

        String ct = data.consumeString(500);
        byte [] input = data.consumeRemainingAsBytes();

        InputStream rawInputStream = new ByteArrayInputStream(input);
        MessageImpl message = new MessageImpl();
        message.setContent(InputStream.class, rawInputStream);
        message.put(Message.CONTENT_TYPE, ct);

        try {
           new AttachmentDeserializer(message).initializeAttachments();
           InputStream inputStreamWithoutAttachments = message.getContent(InputStream.class);
           SAXParser parser = SAXParserFactory.newInstance().newSAXParser();
           parser.parse(inputStreamWithoutAttachments, new DefaultHandler());
           inputStreamWithoutAttachments.close();
           rawInputStream.close();
        } catch (IOException | ParserConfigurationException | SAXException | StringIndexOutOfBoundsException | HeaderSizeExceededException | ArrayIndexOutOfBoundsException e) {
        }
    }
}
