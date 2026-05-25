# OSS-Fuzz latest code coverage

OSS-Fuzz makes code coverage reports publicly available. These
are available at URLS:

https://storage.googleapis.com/oss-fuzz-coverage/$PROJECT_NAME/reports/$DATE/linux/report.html


Where $PROJECT_NAME is the relevant OSS-Fuzz project and $DATE is the date of the coverage report.

For example, the URL https://storage.googleapis.com/oss-fuzz-coverage/gpsd/reports/20260123/linux/report.html holds the coverage report for the `gpsd` project for the 23rd January 2026.

There may not be a coverage report for a given date if the coverage build failed for the project on that date.

There is also structured information in the form of a .json file, on e.g. https://storage.googleapis.com/oss-fuzz-coverage/gpsd/reports/20260123/linux/summary.json

The OSS-Fuzz coverage reports are crucial for working on expanding OSS-Fuzz projects.

These coverage reports hold the data of the collective corpus collected by OSS-Fuzz for all the fuzzing harnesses in a given project.