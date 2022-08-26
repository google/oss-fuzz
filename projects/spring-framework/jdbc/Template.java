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