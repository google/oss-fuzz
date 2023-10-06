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
package jdbc;

public class PersistentClass {
    private Integer m_id;
    private Integer m_int;
    private String  m_string;
    
    public PersistentClass(Integer intMember, String stringMember, Integer id) {
        m_id = id;
        m_int = intMember;
        m_string = stringMember;
    }

    public PersistentClass(Integer intMember, String stringMember) {
        m_int = intMember;
        m_string = stringMember;
    }

    public void setId(Integer id) {
        m_id = id;
    }
    public Integer getId() {
        return m_id;
    }
    public void setIntMember(Integer value) {
        m_int = value;
    }
    public Integer getIntMember() {
        return m_int;
    }
    public void setStringMember(String value) {
        m_string = value;
    }
    public String getStringMember() {
        return m_string;
    }
}