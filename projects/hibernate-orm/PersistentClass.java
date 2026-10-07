import java.math.BigDecimal;
import java.util.Date;
import java.sql.Time;
import java.sql.Timestamp;

public class PersistentClass {
	private int m_id;
	private int m_integer;
	private String m_string;
	private BigDecimal m_bigDecimal;
	private long m_long;
	private short m_short;
	private byte m_byte;
	private boolean m_boolean;
	private Date m_date;
	private Time m_time;
	private Timestamp m_timestamp;
	private SerializableClass m_serializable;
 
	public PersistentClass() {
	}

	public int getId() {
		return m_id;
	}

	public void setId(int id) {
		m_id = id;
	}
 
	public int getIntegerMember() {
		return m_integer;
	}
 
	public void setIntegerMember(int value) {
		m_integer = value;
	}
 
	public String getStringMember() {
		return m_string;
	}
 
	public void setStringMember(String value) {
		m_string = value;
	}

	public BigDecimal getBigDecimalMember() {
		return m_bigDecimal;
	}

	public void setBigDecimalMember(BigDecimal bigDecimal) {
		m_bigDecimal = bigDecimal;
	}
	
	public long getLongMember() {
		return m_long;
	}

	public void setLongMember(long value) {
		m_long = value;
	}

	public short getShortMember() {
		return m_short;
	}

	public void setShortMember(short value) {
		m_short = value;
	}

	public boolean getBooleanMember() {
		return m_boolean;
	}

	public void setBooleanMember(boolean value) {
		m_boolean = value;
	}
	
	public byte getByteMember() {
		return m_byte;
	}
	
	public void setByteMember(byte value) {
		m_byte = value;
	}

	public Date getDateMember() {
		return m_date;
	}
	
	public void setDateMember(Date value) {
		m_date = value;
	}
	
	public Time getTimeMember() {
		return m_time;
	}
	
	public void setTimeMember(Time value) {
		m_time = value;
	}

	public Timestamp getTimestampMember() {
		return m_timestamp;
	}
	
	public void setTimestampMember(Timestamp value) {
		m_timestamp = value;
	}

	public SerializableClass getSerializableClassMember() {
		return m_serializable;
	}

	public void setSerializableClassMember(SerializableClass value) {
		m_serializable = value;
	}
}