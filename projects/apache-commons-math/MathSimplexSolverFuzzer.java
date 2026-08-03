// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.ArrayList;
import org.apache.commons.math4.legacy.exception.DimensionMismatchException;
import org.apache.commons.math4.legacy.exception.TooManyIterationsException;
import org.apache.commons.math4.legacy.optim.linear.NoFeasibleSolutionException;
import org.apache.commons.math4.legacy.optim.linear.UnboundedSolutionException;
import org.apache.commons.math4.legacy.optim.PointValuePair;
import org.apache.commons.math4.legacy.optim.linear.LinearConstraint;
import org.apache.commons.math4.legacy.optim.linear.LinearConstraintSet;
import org.apache.commons.math4.legacy.optim.linear.LinearObjectiveFunction;
import org.apache.commons.math4.legacy.optim.linear.NonNegativeConstraint;
import org.apache.commons.math4.legacy.optim.linear.PivotSelectionRule;
import org.apache.commons.math4.legacy.optim.linear.SimplexSolver;
import org.apache.commons.math4.legacy.optim.linear.Relationship;
import org.apache.commons.math4.legacy.optim.nonlinear.scalar.GoalType;
import org.apache.commons.math4.legacy.optim.MaxIter;

public class MathSimplexSolverFuzzer {

	protected LinearObjectiveFunction m_function;
	protected ArrayList<LinearConstraint> m_constraints;
	protected GoalType m_goal;
	protected PivotSelectionRule m_pivotSelectionRule;


	double[] coefficients(FuzzedDataProvider fuzzedDataProvider) {
		return new double[]{ fuzzedDataProvider.consumeRegularDouble(), fuzzedDataProvider.consumeRegularDouble(), fuzzedDataProvider.consumeRegularDouble() };
	}

	double rightHandSide(FuzzedDataProvider fuzzedDataProvider) {
		return fuzzedDataProvider.consumeRegularDouble();
	}

	Relationship relation(FuzzedDataProvider fuzzedDataProvider) {
		Relationship available[] = { Relationship.EQ, Relationship.GEQ, Relationship.LEQ };
		return available[fuzzedDataProvider.consumeInt(0, available.length-1)];
	}

	GoalType goalType(FuzzedDataProvider fuzzedDataProvider) {
		GoalType available[] = { GoalType.MAXIMIZE, GoalType.MINIMIZE };
		return available[fuzzedDataProvider.consumeInt(0, available.length-1)];
	}

	PivotSelectionRule pivotSelectionRule(FuzzedDataProvider fuzzedDataProvider) {
		PivotSelectionRule available[] = { PivotSelectionRule.DANTZIG, PivotSelectionRule.BLAND };
		return available[fuzzedDataProvider.consumeInt(0, available.length-1)];
	}

	public MathSimplexSolverFuzzer(FuzzedDataProvider fuzzedDataProvider) {
	
		m_function = new LinearObjectiveFunction(coefficients(fuzzedDataProvider), 0);
		m_constraints = new ArrayList<>();
		
		m_constraints.add(new LinearConstraint(coefficients(fuzzedDataProvider), relation(fuzzedDataProvider), rightHandSide(fuzzedDataProvider)));
		m_constraints.add(new LinearConstraint(coefficients(fuzzedDataProvider), relation(fuzzedDataProvider), rightHandSide(fuzzedDataProvider)));
		m_constraints.add(new LinearConstraint(coefficients(fuzzedDataProvider), relation(fuzzedDataProvider), rightHandSide(fuzzedDataProvider)));

		m_goal = goalType(fuzzedDataProvider);
		m_pivotSelectionRule = pivotSelectionRule(fuzzedDataProvider);
	}

	void solve() {
		SimplexSolver solver = new SimplexSolver();
		try {
			solver.optimize(
				new MaxIter(1000),
				m_function,
				new LinearConstraintSet(m_constraints),
				m_goal,
				new NonNegativeConstraint(true),
				m_pivotSelectionRule
			);
		} catch(TooManyIterationsException ex) {
			/* documented, ignore */
		} catch(NoFeasibleSolutionException ex) {
			/* documented? */
		} catch(UnboundedSolutionException ex) {
			/* documented? */
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		MathSimplexSolverFuzzer testClosure = new MathSimplexSolverFuzzer(data);
		testClosure.solve();
	}
}
