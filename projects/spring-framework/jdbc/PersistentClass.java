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