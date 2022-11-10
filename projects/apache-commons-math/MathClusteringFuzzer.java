import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.ArrayList;
import org.apache.commons.math4.legacy.exception.ConvergenceException;
import org.apache.commons.math4.legacy.exception.MathIllegalArgumentException;
import org.apache.commons.math4.legacy.exception.NotPositiveException;
import org.apache.commons.math4.legacy.ml.clustering.Clusterer;
import org.apache.commons.math4.legacy.ml.clustering.DBSCANClusterer;
import org.apache.commons.math4.legacy.ml.clustering.DoublePoint;
import org.apache.commons.math4.legacy.ml.clustering.ElkanKMeansPlusPlusClusterer;
import org.apache.commons.math4.legacy.ml.clustering.FuzzyKMeansClusterer;
import org.apache.commons.math4.legacy.ml.clustering.KMeansPlusPlusClusterer;
import org.apache.commons.math4.legacy.ml.clustering.MultiKMeansPlusPlusClusterer;


public class MathClusteringFuzzer {

	protected int    m_clustersToFind;
	protected int    m_iterations;
	protected double m_fuzziness;
	protected int    m_multiKMeansMaxTrials;
	protected double m_dbscanMaxRadius;
	protected int    m_dbscanMinPoints;
	protected ArrayList<DoublePoint> m_data;

	public MathClusteringFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		m_clustersToFind = fuzzedDataProvider.consumeInt(1, 10); // let's be "sane" ... for the beginning
		m_iterations = fuzzedDataProvider.consumeInt(1, 10000); // again
		m_fuzziness = fuzzedDataProvider.consumeRegularDouble();
		m_multiKMeansMaxTrials = fuzzedDataProvider.consumeInt(0, 10);
		m_dbscanMaxRadius = fuzzedDataProvider.consumeRegularDouble();
		m_dbscanMinPoints = fuzzedDataProvider.consumeInt();

		int dimension = 2;
		int inputLength = (fuzzedDataProvider.remainingBytes() / 8 /*sizeof(double)*/) / dimension;
		if (inputLength < 1) {
			inputLength = 1;
		}

		m_data = new ArrayList<DoublePoint>(inputLength);
		for (int i = 0; i < inputLength; ++i) {
			double dataPoint[] = new double[dimension];
			for (int n = 0; n < dataPoint.length; ++n) {
				dataPoint[n] = fuzzedDataProvider.consumeRegularDouble();
			}
			m_data.add( new DoublePoint(dataPoint) );
		}
	}

	void runDBSCAN() {
		try {
			DBSCANClusterer<DoublePoint> clusterer = new DBSCANClusterer<DoublePoint>(m_dbscanMaxRadius, m_dbscanMinPoints);
			clusterer.cluster(m_data);
		} catch (NotPositiveException ex) {
			/* documented, ignore */
		}
	}

	void runElkanKMeansPlusPlus() {
		try {
			ElkanKMeansPlusPlusClusterer<DoublePoint> clusterer = new ElkanKMeansPlusPlusClusterer<DoublePoint>(m_clustersToFind);
			clusterer.cluster(m_data);
		} catch (MathIllegalArgumentException ex) {
			/* documented, ignore */
		} catch (ConvergenceException ex) {
			/* documented, ignore */
		}
	}

	void runKMeansPlusPlus() {
		try {
			KMeansPlusPlusClusterer<DoublePoint> clusterer = new KMeansPlusPlusClusterer<DoublePoint>(m_clustersToFind, m_iterations);
			clusterer.cluster(m_data);
		} catch (MathIllegalArgumentException ex) {
			/* documented, ignore */
		} catch (ConvergenceException ex) {
			/* documented, ignore */
		}
	}

	void runFuzzyKMeans() {
		try {
			FuzzyKMeansClusterer<DoublePoint> clusterer = new FuzzyKMeansClusterer<DoublePoint>(m_clustersToFind, m_fuzziness);
			clusterer.cluster(m_data);
		} catch (MathIllegalArgumentException ex) {
			/* documented, ignore */
		} catch (ConvergenceException ex) {
			/* documented, ignore */
		}
	}

	void runMultiKMeans() {
		try {
			KMeansPlusPlusClusterer<DoublePoint> kmeans = new KMeansPlusPlusClusterer<DoublePoint>(m_clustersToFind, m_iterations);
			MultiKMeansPlusPlusClusterer<DoublePoint> clusterer = new MultiKMeansPlusPlusClusterer<DoublePoint>(kmeans, m_multiKMeansMaxTrials);
			clusterer.cluster(m_data);
		} catch (MathIllegalArgumentException ex) {
			/* documented, ignore */
		} catch (ConvergenceException ex) {
			/* documented, ignore */
		}
	}





	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		MathClusteringFuzzer testClosure = new MathClusteringFuzzer(data);
		
		testClosure.runDBSCAN();
		testClosure.runKMeansPlusPlus();
		testClosure.runFuzzyKMeans();
		testClosure.runElkanKMeansPlusPlus();
		testClosure.runMultiKMeans();
	}
}
