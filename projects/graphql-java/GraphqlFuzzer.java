// Copyright 2023 Google LLC
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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import graphql.GraphQL;
import graphql.GraphQLException;
import graphql.schema.GraphQLSchema;
import graphql.schema.idl.RuntimeWiring;
import graphql.schema.idl.SchemaGenerator;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.TypeDefinitionRegistry;

public class GraphqlFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    GraphQLSchema graphQLSchema;
    SchemaParser schemaParser = new SchemaParser();
    SchemaGenerator schemaGenerator = new SchemaGenerator();

    try {
      if (data.consumeBoolean()) {
        TypeDefinitionRegistry registry =
            schemaParser.parse(data.consumeString(data.remainingBytes() / 2));
        graphQLSchema = schemaGenerator.makeExecutableSchema(
            registry, RuntimeWiring.newRuntimeWiring().build());
      } else {
        graphQLSchema =
            schemaGenerator.createdMockedSchema(data.consumeString(data.remainingBytes() / 2));
      }

      GraphQL.newGraphQL(graphQLSchema).build().execute(data.consumeRemainingAsString());
    } catch (GraphQLException e) {
      // Known exception
    }
  }
}
