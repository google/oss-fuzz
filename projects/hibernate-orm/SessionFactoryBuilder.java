import org.hibernate.HibernateException;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
 
public class SessionFactoryBuilder {
    public static SessionFactory sessionFactory() {
        SessionFactory sessionFactory = null;
        try {
            Configuration configuration = new Configuration(); 
            //Initialize the configuration object 
            //with the configuration file data
        	configuration.configure("hibernate.xml");
        	// Get the SessionFactory object from configuration.
        	sessionFactory = configuration.buildSessionFactory();
        } catch (Exception e) {
             e.printStackTrace();
        }
        return sessionFactory;
    }
 
}