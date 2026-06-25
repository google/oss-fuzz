import os
import sys
from unittest.mock import MagicMock

# Create a mock for atheris so we can test the logic without having atheris installed locally
class MockInstrument:
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

mock_atheris = MagicMock()
mock_atheris.instrument_imports.return_index = 0
mock_atheris.instrument_imports.return_value = MockInstrument()

sys.modules['atheris'] = mock_atheris

# Inject local directory to system path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def run_fuzzer_locally():
    # Import locally inside the function so that coverage measurement is set up BEFORE import
    import fuzz_tomlkit
    
    print("Beginning offline validation of the fuzz harness logic against seed corpus...")
    
    seed_dir = "/tmp/seed_test"
    if not os.path.exists(seed_dir):
        print(f"Error: {seed_dir} does not exist. Generating them first...")
        import generate_seeds
        # Mock sys.argv to safely invoke generate_seeds
        old_argv = sys.argv
        sys.argv = [old_argv[0], seed_dir]
        generate_seeds.main()
        sys.argv = old_argv
        
    passed = 0
    failed = 0
    
    seeds = os.listdir(seed_dir)
    for filename in seeds:
        filepath = os.path.join(seed_dir, filename)
        print(f"Testing seed: {filename}...")
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            fuzz_tomlkit.TestOneInput(data)
            print(f" -> {filename} passed successfully.")
            passed += 1
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f" -> {filename} failed: {e}")
            failed += 1
            
    print(f"\nValidation Summary: Passed={passed}, Failed={failed}")
    if failed > 0:
        sys.exit(1)
    else:
        print("Success! Fuzzer logic is production-ready.")

if __name__ == "__main__":
    # If the user requested coverage report, let's guide them or run it programmatically
    if "--coverage" in sys.argv:
        try:
            import coverage
            print("Initializing coverage collector...")
            cov = coverage.Coverage(source=['tomlkit'])
            cov.start()
            
            # Run the fuzzer (which will import and run tomlkit)
            run_fuzzer_locally()
            
            cov.stop()
            cov.save()
            
            print("\n================== CODE COVERAGE REPORT ==================")
            cov.report(show_missing=True)
            
            html_dir = "tomlkit_fuzzer/htmlcov"
            cov.html_report(directory=html_dir)
            print(f"==========================================================")
            print(f"Interactive HTML report generated at: {html_dir}/index.html")
        except ImportError:
            print("Error: 'coverage' package is not installed. Install it with: pip install coverage")
            sys.exit(1)
    else:
        run_fuzzer_locally()
        print("\nTip: Run this script with '--coverage' to generate detailed coverage metrics.")
