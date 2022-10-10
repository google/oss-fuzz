import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import org.hibernate.HibernateException;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.Session;
import org.hibernate.Session;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.SQLException;


public class PersistentClassFuzzer extends TestServer {

	final private String tableName = "PersistentClassStore";
	final private String className = "PersistentClass";
	
	PersistentClass m_persistentClass = null;

	PersistentClassFuzzer(FuzzedDataProvider fuzzedDataProvider, boolean verbose) {
		super(verbose);

		try {
			dropTable(tableName);
		} catch(SQLException ex) {
			ex.printStackTrace(System.out);
			/* cannot happen? */
		}

		m_persistentClass = new PersistentClass();
		m_persistentClass.setIntegerMember(fuzzedDataProvider.consumeInt());
		m_persistentClass.setBigDecimalMember(new BigDecimal(fuzzedDataProvider.consumeInt()));
		m_persistentClass.setShortMember(fuzzedDataProvider.consumeShort());
		m_persistentClass.setLongMember(fuzzedDataProvider.consumeLong());
		m_persistentClass.setBooleanMember(fuzzedDataProvider.consumeBoolean());
		m_persistentClass.setByteMember(fuzzedDataProvider.consumeByte());
		m_persistentClass.setDateMember(new Date(fuzzedDataProvider.consumeLong()));
		m_persistentClass.setTimeMember(new Time(fuzzedDataProvider.consumeLong()));
		m_persistentClass.setTimestampMember(new Timestamp(fuzzedDataProvider.consumeLong()));
		m_persistentClass.setSerializableClassMember(
			new SerializableClass(
				fuzzedDataProvider.consumeInt(),
				fuzzedDataProvider.consumeString(8)
			)
		);
		m_persistentClass.setStringMember(fuzzedDataProvider.consumeRemainingAsAsciiString());
	}

	boolean persist() {
		boolean retval;

		Transaction tx = null;
		Session session = SessionFactoryBuilder.sessionFactory().openSession();
		try {
			tx = session.beginTransaction();
			session.save(m_persistentClass);
			tx.commit();
			retval = true;
		} catch (HibernateException e) {
			if (tx != null) {
				tx.rollback();
			}
			retval = false;
		} finally {
			session.close(); 
		}

		return retval;
	}

	void restore()
	{
		Session session = SessionFactoryBuilder.sessionFactory().openSession();
		Transaction tx = null;

		try {
			tx = session.beginTransaction();

			List allPersistentClasses = session.createQuery("FROM " + className).list();
			List<PersistentClass> persistentClasses = (List<PersistentClass>)allPersistentClasses;
			for(PersistentClass pc : persistentClasses) {
				if (pc.getIntegerMember() != m_persistentClass.getIntegerMember()) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <int>");
				}
				if (!pc.getStringMember().equals(m_persistentClass.getStringMember())) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <string>");
				}
				if (pc.getBigDecimalMember().compareTo(m_persistentClass.getBigDecimalMember()) != 0) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <BigDecimal>");
				}
				
				if (pc.getLongMember() != m_persistentClass.getLongMember()) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <long>");
				}
				if (pc.getShortMember() != m_persistentClass.getShortMember()) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <short>");
				}
				if (pc.getBooleanMember() != m_persistentClass.getBooleanMember()) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <boolean>");
				}
				if (pc.getByteMember() != m_persistentClass.getByteMember()) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <byte>");
				}
				if (!pc.getDateMember().equals(m_persistentClass.getDateMember())) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <Date>");
				}
				if (!pc.getTimeMember().equals(m_persistentClass.getTimeMember())) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <Time>");
				}
				if (!pc.getTimestampMember().equals(m_persistentClass.getTimestampMember())) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <Timestamp>");
				}
				if (!pc.getSerializableClassMember().equals(m_persistentClass.getSerializableClassMember())) {
					throw new FuzzerSecurityIssueHigh("Restore failed for <Serializable>");
				}
			}
			tx.commit();
		} catch (HibernateException e) {
			if (tx != null) {
				tx.rollback();
			}
		} finally {
			session.close(); 
		}
	}

	void testOneInput() {
		if (persist()) {
			restore();
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		try (PersistentClassFuzzer testClosure = new PersistentClassFuzzer(fuzzedDataProvider, false)) {
			testClosure.testOneInput();
		}
	}
} 