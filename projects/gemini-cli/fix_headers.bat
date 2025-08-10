@echo off
REM Fix all license headers

echo Fixing license headers...

REM Files that need headers added
set "files_need_headers=gofuzz\fuzz\fuzz_oauth_token.go gofuzz\fuzz\fuzz_oauth_token_request.go gofuzz\fuzz\fuzz_oauth_token_response.go gofuzz\internal\cli\parse.go gofuzz\internal\config\parse.go gofuzz\internal\mcp\decode.go gofuzz\internal\oauth\token.go"

REM Also fix Dockerfile and project.yaml
echo Fixing Dockerfile...
powershell -Command "(Get-Content Dockerfile) -replace 'Google Inc', 'Google LLC' | Set-Content Dockerfile"

echo Fixing project.yaml...
powershell -Command "(Get-Content project.yaml) -replace 'Google Inc', 'Google LLC' | Set-Content project.yaml"

echo Done!
