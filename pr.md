# fix(ci): Correct and improve Ubuntu version sync workflow

This PR addresses several issues in the `Ubuntu Version Sync` workflow to improve its reliability and clarity.

The workflow was previously failing due to a bash syntax error and was incorrectly applying Dockerfile checks to project-specific files.

Key changes:

- **Corrected Bash Syntax:** Fixed the syntax for associative array iteration in the `run` step, resolving the `Unexpected symbol: ' @'` error.
- **Scoped Dockerfile Checks:** The synchronization check for Dockerfiles is now strictly limited to the `infra/` directory. This prevents the workflow from failing on PRs that only modify Dockerfiles within `projects/`.
- **Improved Workflow Name:** Renamed the workflow to `Ubuntu Version Sync Check` for better readability in PR status checks, instead of displaying the raw filename.
