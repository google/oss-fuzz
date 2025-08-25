<!-- Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. -->

# Java Fuzz Targets for Gemini CLI

This directory contains Java fuzz targets for the Gemini CLI project, providing comprehensive security testing for JVM-based components.

## Components

### OAuthTokenRequestParser
A robust OAuth token request parser that handles various input formats:
- JSON parsing with Jackson
- URL-encoded form data
- Base64 encoded data
- Input validation and sanitization

### FuzzOAuthTokenRequest
Jazzer-based fuzz target that tests:
- Multiple input parsing strategies
- Validation logic
- Serialization/deserialization
- Error handling

## Building

```bash
# Compile Java components
mvn clean compile

# Run tests
mvn test

# Build with Jazzer fuzzing support
mvn compile -Pjazzer
```

## Fuzzing

The Java fuzz targets are integrated with OSS-Fuzz and use Jazzer for JVM fuzzing:

```bash
# Run fuzz target directly
mvn exec:java -Dexec.mainClass="com.gemini.cli.FuzzOAuthTokenRequest"

# Run with OSS-Fuzz
./build.sh
```

## Security Coverage

- OAuth token parsing vulnerabilities
- JSON injection attacks
- Input validation bypasses
- Serialization/deserialization issues
- Memory exhaustion attacks
- Malformed data handling

## Dependencies

- **Jackson Databind**: JSON parsing and serialization
- **JUnit 5**: Unit testing framework
- **Jazzer**: JVM fuzzing framework
- **SLF4J**: Logging framework
- **Apache Commons Lang**: Utility functions

## Configuration

The `pom.xml` includes profiles for:
- **default**: Standard compilation and testing
- **oss-fuzz**: Jazzer integration for OSS-Fuzz
- **coverage**: JaCoCo code coverage reporting
