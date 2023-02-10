package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.log4j.*;

public class LoggerFuzzer {
	protected String m_fqcn;
	protected Level m_level;
	protected String m_diagnostic;
	protected Exception m_throwable;
	protected String m_key;
	protected Object[] m_params;

	LoggerFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		int n = fuzzedDataProvider.consumeInt(0, 10);
		m_params = new Object[n];
		for(int i=0; i<n; ++i) {
			switch(fuzzedDataProvider.consumeInt(0,3)) {
				case 0:
					m_params[i] = new Integer(fuzzedDataProvider.consumeInt());
					break;
				case 1:
					m_params[i] = new Double(fuzzedDataProvider.consumeDouble());
					break;
				case 2:
					m_params[i] = new String(fuzzedDataProvider.consumeString(16));
					break;
			}
		}

		m_fqcn = fuzzedDataProvider.consumeString(16);
		m_key  = fuzzedDataProvider.consumeString(16);
		m_level = Level.toLevel(fuzzedDataProvider.consumeInt());
		m_diagnostic = fuzzedDataProvider.consumeRemainingAsString();
		m_throwable = new NullPointerException();
	}

	void test() {
		Logger logger = Logger.getLogger(LoggerFuzzer.class);

		logger.addAppender(new MyAppender());
		
		/*
		 * the popular ones
		 */
		logger.debug(m_diagnostic);
		logger.error(m_diagnostic);
		logger.fatal(m_diagnostic);
		logger.info(m_diagnostic);
		logger.trace(m_diagnostic);

		/*
         * not so popular
		 */
		 logger.log(m_level, m_diagnostic);
		 logger.log(m_fqcn, m_level, m_diagnostic, m_throwable);
		 logger.l7dlog(m_level, m_key, m_throwable);
		 logger.l7dlog(m_level, m_key, m_params, m_throwable);
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		LoggerFuzzer testClosure = new LoggerFuzzer(fuzzedDataProvider);
		testClosure.test();
		
		
	}
}