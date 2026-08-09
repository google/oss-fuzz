import java.io.Serializable;

public class SerializableClass implements Serializable {
	int m_intMember;
	String m_stringMember;

	public SerializableClass() {
	}

	public SerializableClass(int intMember, String stringMember) {
		m_intMember = intMember;
		m_stringMember = stringMember;
	}

	void setIntMember(int value) {
		m_intMember = value;
	}

	int getIntMember() {
		return m_intMember;
	}

	void setStringMember(String value) {
		m_stringMember = value;
	}

	String getStringMember() {
		return m_stringMember;
	}

	public boolean equals(Object other) {
		SerializableClass sc = null;
		if (other instanceof SerializableClass) {
			sc = (SerializableClass)other;
		}

		if (sc != null) {
			return getIntMember() == sc.getIntMember() && getStringMember().equals(sc.getStringMember());
		}
		return false;
	}
} 