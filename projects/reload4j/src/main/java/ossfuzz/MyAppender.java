package ossfuzz;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.spi.LoggingEvent;

public class MyAppender extends AppenderSkeleton {
	public MyAppender() {
	}

	@Override
	public void append(LoggingEvent event) {
		//System.out.println(event.getRenderedMessage());
	}
	@Override
	public synchronized void close() {
		if (this.closed) {
			return;
		}
		this.closed = true;
	}
	
	@Override
    public boolean requiresLayout() {
		return false;
	}
}