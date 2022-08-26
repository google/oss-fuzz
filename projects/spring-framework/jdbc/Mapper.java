package jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.jdbc.core.RowMapper;

public class Mapper implements RowMapper<PersistentClass> {
    public PersistentClass mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new PersistentClass(
            rs.getInt("intMember"),
            rs.getString("stringMember"),
            rs.getInt("id")
        );
    }
}