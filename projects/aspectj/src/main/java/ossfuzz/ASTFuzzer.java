package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.HashMap;

import org.aspectj.org.eclipse.jdt.core.dom.AST;
import org.aspectj.org.eclipse.jdt.core.dom.ASTParser;
import org.aspectj.org.eclipse.jdt.core.dom.CompilationUnit;

public class ASTFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		try {
			int astlevel = fuzzedDataProvider.consumeInt();
			String source = fuzzedDataProvider.consumeRemainingAsString();
		
			ASTParser parser = ASTParser.newParser(astlevel);
			parser.setSource(source.toCharArray());
			parser.setCompilerOptions(new HashMap());
			CompilationUnit cu = (CompilationUnit) parser.createAST(null);
			cu.getAST();
		} catch (IllegalArgumentException ex) {
			/* ignore */
		}
	}
}