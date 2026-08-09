/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.util.ArrayList;
import java.util.List;
import java.sql.SQLException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import jdbc.*;

public class JdbcCoreMapperFuzzer extends MapperFuzzerServer {
    List<PersistentClass> m_persistentClasses = null;

    JdbcCoreMapperFuzzer(FuzzedDataProvider data) {
        super(false);

        m_persistentClasses = new ArrayList<PersistentClass>();
        int n = data.consumeInt(1,10);
        for(int i = 0; i < n; ++i) {
            m_persistentClasses.add(new PersistentClass(data.consumeInt(), data.consumeAsciiString(10)));
        }
    }

    boolean containedIn(PersistentClass needle, List<PersistentClass> haystack) {
        for (PersistentClass rval : haystack) {
            /*
             * id is allowed to mismatch.
             */
            if (!needle.getIntMember().equals(rval.getIntMember())) {
                continue;
            }
            if (!needle.getStringMember().equals(rval.getStringMember())) {
                continue;
            }
            return true;
        }
        return false;
    }

    void verifyPersistentClasses(List<PersistentClass> persistentClasses) {
        
        if (persistentClasses.size() != m_persistentClasses.size()) {
            throw new FuzzerSecurityIssueLow("Data loss detected");
        }

        for (PersistentClass expectedClass : m_persistentClasses) {
            if (! containedIn(expectedClass, persistentClasses)) {
                throw new FuzzerSecurityIssueLow("Data corruption detected");
            }
        }
    }

    void persistData(Template template) {
        for(PersistentClass persistentClass : m_persistentClasses) {
            template.create(persistentClass);
        }

        List<PersistentClass> persistedClasses = template.listPersistentClasses();
        verifyPersistentClasses(persistedClasses);

        /*
         * the list from the template contains IDs.
         */
        m_persistentClasses = persistedClasses;
    }

    void updateData(Template template, FuzzedDataProvider data) {
        int k = data.consumeInt(0, m_persistentClasses.size()-1);
        PersistentClass persistentClass = m_persistentClasses.get(k);
        persistentClass.setIntMember(data.consumeInt());
        persistentClass.setStringMember(data.consumeString(10));
        m_persistentClasses.set(k, persistentClass);
        template.update(persistentClass);

        List<PersistentClass> persistedClasses = template.listPersistentClasses();
        verifyPersistentClasses(persistedClasses);
    }

    void removeData(Template template, FuzzedDataProvider data) {
        int k = data.consumeInt(0, m_persistentClasses.size()-1);
        PersistentClass persistentClass = m_persistentClasses.remove(k);
        template.remove(persistentClass);

        List<PersistentClass> persistedClasses = template.listPersistentClasses();
        verifyPersistentClasses(persistedClasses);
    }

    void runTests(FuzzedDataProvider data) {
        try {
            prepareTables();
        } catch (SQLException ex) {
            /* this should really not happen */
            ex.printStackTrace(System.err);
            System.exit(1);
        }

        ApplicationContext context = new ClassPathXmlApplicationContext("JdbcCoreMapperFuzzerBeans.xml");
        Template template = (Template)context.getBean("persistentClassJdbcTemplate");

        persistData(template);
        updateData(template, data);
        removeData(template, data);
    }
    
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        JdbcCoreMapperFuzzer testClosure = new JdbcCoreMapperFuzzer(data);
        testClosure.runTests(data);
        testClosure.stop();
    }
}