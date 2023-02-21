#!/usr/bin/python3
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import atheris
import connexion

from werkzeug.datastructures import MultiDict


def fixed_params(data):
  """Create a given URI parser and pass in fixed params for the URI object
  and a random query."""
  fdp = atheris.FuzzedDataProvider(data)
  collection_formats = ['csv', 'pipes', 'multi']
  parameters = [{
      "name": "letters",
      "in": "query",
      "type": "string",
      "items": {
          "type": "string"
      },
      "collectionFormat": fdp.PickValueInList(collection_formats),
  }]

  parser_classes = [
      connexion.uri_parsing.OpenAPIURIParser,
      connexion.uri_parsing.Swagger2URIParser,
      connexion.uri_parsing.AlwaysMultiURIParser,
      connexion.uri_parsing.FirstValueURIParser,
  ]
  parser_class = fdp.PickValueInList(parser_classes)
  parser = parser_class(parameters, {})
  param_dict = MultiDict([
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24)),
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24)),
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24)),
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24))
  ])
  parser.resolve_query(param_dict.to_dict(flat=False))


def arbitrary(data):
  """Create a given URI parser and pass in random params as well as random
  query params."""
  fdp = atheris.FuzzedDataProvider(data)
  collection_formats = ['csv', 'pipes', 'multi']
  parameters = [{
      fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24),
      fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24),
      fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24),
      fdp.ConsumeUnicodeNoSurrogates(24): {
          fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24)
      },
      "collectionFormat": fdp.PickValueInList(collection_formats),
  }]

  parser_classes = [
      connexion.uri_parsing.OpenAPIURIParser,
      connexion.uri_parsing.Swagger2URIParser,
      connexion.uri_parsing.AlwaysMultiURIParser,
      connexion.uri_parsing.FirstValueURIParser,
  ]
  parser_class = fdp.PickValueInList(parser_classes)
  try:
    parser = parser_class(parameters, {})
  except KeyError:
    return
  param_dict = MultiDict([
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24)),
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24)),
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24)),
      (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24))
  ])
  parser.resolve_query(param_dict.to_dict(flat=False))


def TestOneInput(data):
  fixed_params(data)
  arbitrary(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
