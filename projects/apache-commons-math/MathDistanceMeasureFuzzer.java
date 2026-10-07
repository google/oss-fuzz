import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.ArrayList;
import org.apache.commons.math4.legacy.exception.DimensionMismatchException;
import org.apache.commons.math4.legacy.ml.distance.CanberraDistance;
import org.apache.commons.math4.legacy.ml.distance.ChebyshevDistance;
import org.apache.commons.math4.legacy.ml.distance.EarthMoversDistance;
import org.apache.commons.math4.legacy.ml.distance.EuclideanDistance;
import org.apache.commons.math4.legacy.ml.distance.ManhattanDistance;

public class MathDistanceMeasureFuzzer {
	double m_x0[];
	double m_x1[];

	public MathDistanceMeasureFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		m_x0 = new double[fuzzedDataProvider.consumeInt(1,100)];
		m_x1 = new double[fuzzedDataProvider.consumeInt(1,100)];
		for (int i = 0; i < m_x0.length; ++i) {
			m_x0[i] = fuzzedDataProvider.consumeRegularDouble();
		}
		for (int i = 0; i < m_x1.length; ++i) {
			m_x1[i] = fuzzedDataProvider.consumeRegularDouble();
		}
	}

	void computeDistances() {
		try {
			new CanberraDistance().compute(m_x0, m_x1);
			new ChebyshevDistance().compute(m_x0, m_x1);
			new EarthMoversDistance().compute(m_x0, m_x1);
			new EuclideanDistance().compute(m_x0, m_x1);
			new ManhattanDistance().compute(m_x0, m_x1);
		} catch (DimensionMismatchException ex) {
			/* documented, ignore */
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		MathDistanceMeasureFuzzer testClosure = new MathDistanceMeasureFuzzer(data);
		testClosure.computeDistances();
	}
}