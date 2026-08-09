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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import jakarta.activation.DataHandler;
import jakarta.mail.util.ByteArrayDataSource;

import org.apache.cxf.helpers.IOUtils;
import org.apache.cxf.message.Attachment;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.attachment.AttachmentImpl;
import org.apache.cxf.attachment.AttachmentSerializer;
import org.apache.cxf.attachment.AttachmentDeserializer;
import org.apache.cxf.attachment.HeaderSizeExceededException;

public class AttachmentSerializerDeserializerFuzzer {

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        MessageImpl in = new MessageImpl();
        MessageImpl msg = new MessageImpl();
        Collection<Attachment> atts = new ArrayList<>();

        String str0 = data.consumeString(250);
        AttachmentImpl a = new AttachmentImpl(str0);

        byte [] byteArr = data.consumeBytes(250);
        InputStream is = new ByteArrayInputStream(byteArr);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ByteArrayDataSource ds = null;
        String str1 = data.consumeString(250);
        try {
            ds = new ByteArrayDataSource(is, str1);
        } catch (IOException e) {
            return;
        }

        a.setDataHandler(new DataHandler(ds));
        atts.add(a);
        in.setAttachments(atts);

        String str2 = data.consumeString(250);
        in.put(Message.CONTENT_TYPE, str2);
        in.setContent(OutputStream.class, out);

        AttachmentSerializer serializer = new AttachmentSerializer(in);
        boolean xop = data.consumeBoolean();
        if (!xop) {
            serializer.setXop(xop);
        }

        byte [] byteArr2 = data.consumeBytes(250);
        try {
            serializer.writeProlog();
            out.write(byteArr2);
            serializer.writeAttachments();
            out.flush();
        } catch (IOException | StringIndexOutOfBoundsException | IllegalArgumentException e) {
            return;
        }

        String str3 = data.consumeString(250);
        msg.put(Message.CONTENT_TYPE, str3);
        ByteArrayOutputStream baos = (ByteArrayOutputStream)in.getContent(OutputStream.class);
        try {
            ByteArrayInputStream content = new ByteArrayInputStream(baos.toByteArray());
            msg.setContent(InputStream.class, content);

            AttachmentDeserializer deserializer = new AttachmentDeserializer(msg);
            deserializer.initializeAttachments();

            Collection<Attachment> attsCollection = msg.getAttachments();
            Iterator<Attachment> itr = attsCollection.iterator();
            Attachment att = itr.next();

            // check the cached output stream
            InputStream attBody = msg.getContent(InputStream.class);
            ByteArrayOutputStream attOut = new ByteArrayOutputStream();
            IOUtils.copy(attBody, attOut);
            is.close();
        } catch (IOException | HeaderSizeExceededException | IndexOutOfBoundsException e) {
        }
    }
}

