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

import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

public class Template implements DataAccessObject {
    private DataSource m_dataSource;
    private JdbcTemplate m_jdbcTemplate;
    
    public void setDataSource(DataSource dataSource) {
        m_dataSource = dataSource;
        m_jdbcTemplate = new JdbcTemplate(dataSource);
    }
    public void create(PersistentClass persistentClass) {
        m_jdbcTemplate.update("INSERT INTO PersistentClass (stringMember, intMember) VALUES (?, ?)", persistentClass.getStringMember(), persistentClass.getIntMember());
    }
    public void remove(PersistentClass persistentClass) {
        m_jdbcTemplate.update("DELETE FROM PersistentClass WHERE id=?", persistentClass.getId());
    }
    public void update(PersistentClass persistentClass) {
        m_jdbcTemplate.update("UPDATE PersistentClass SET (stringMember, intMember)=(?, ?) WHERE id=?", persistentClass.getStringMember(), persistentClass.getIntMember(), persistentClass.getId());
    }
    public List<PersistentClass> listPersistentClasses() {
        return m_jdbcTemplate.query("SELECT * FROM PersistentClass", new Mapper());
    }
}