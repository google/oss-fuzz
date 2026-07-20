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

package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.HashMap;

import org.aspectj.org.eclipse.jdt.core.dom.AST;
import org.aspectj.org.eclipse.jdt.core.dom.ASTParser;
import org.aspectj.org.eclipse.jdt.core.dom.CompilationUnit;

public class ASTFuzzer {
	// Valid AST JLS levels supported by AspectJ/Eclipse JDT
	private static final int[] VALID_AST_LEVELS = {
		AST.JLS2,   // 2
		AST.JLS3,   // 3
		AST.JLS4,   // 4
		AST.JLS8,   // 8
		AST.JLS9,   // 9
		AST.JLS10,  // 10
		AST.JLS11,  // 11
		AST.JLS12,  // 12
		AST.JLS13,  // 13
		AST.JLS14,  // 14
		AST.JLS15,  // 15
		AST.JLS16,  // 16
		AST.JLS17,  // 17
		AST.JLS18,  // 18
		AST.JLS19,  // 19
		AST.JLS20,  // 20
	};

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		try {
			int astlevel = fuzzedDataProvider.pickValue(VALID_AST_LEVELS);
			String source = fuzzedDataProvider.consumeRemainingAsString();
		
			ASTParser parser = ASTParser.newParser(astlevel);
			parser.setSource(source.toCharArray());
			parser.setCompilerOptions(new HashMap());
			CompilationUnit cu = (CompilationUnit) parser.createAST(null);
			cu.getAST();
		} catch (IllegalArgumentException | VerifyError | NoClassDefFoundError ex) {
			/* ignore - IllegalArgumentException for invalid inputs, 
			   VerifyError/NoClassDefFoundError for bytecode issues during class loading */
		}
	}
}
