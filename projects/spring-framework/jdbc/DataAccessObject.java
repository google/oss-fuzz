package jdbc;

import java.util.List;
import javax.sql.DataSource;

public interface DataAccessObject {
	public void setDataSource(DataSource ds);
	public void create(PersistentClass persistentClass);
	public void remove(PersistentClass persistentClass);
	public void update(PersistentClass persistentClass);
	public List<PersistentClass> listPersistentClasses();
}