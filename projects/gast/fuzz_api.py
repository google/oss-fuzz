#!/usr/bin/python3
# Copyright 2025 Google LLC
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
import ast, gast

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  source = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
  try:
    tree = gast.parse(source)
  except:  # catch it all
    return

  # Any valid tree should be processable
  try:
    gtree = gast.ast_to_gast(tree)
  except RecursionError:
    pass
  gast.dump(gtree)
  for node in gast.walk(gtree):
      if isinstance(node, gast.AST):
          node_copy = type(node)(**dict(gast.iter_fields(node)))
          gast.copy_location(node_copy, node)
          gast.fix_missing_locations(node_copy)
          if isinstance(node, (gast.AsyncFunctionDef, gast.FunctionDef, gast.ClassDef, gast.Module)):
            gast.get_docstring(node)
          gast.get_source_segment(source, node)
          list(gast.iter_child_nodes(node))
          list(gast.iter_fields(node))
          try:
            gast.literal_eval(node)
          except ValueError:
            ...
  gast.increment_lineno(gtree)

  gcode = gast.unparse(gtree)
  gtree2 = gast.parse(gcode)
  gcode2 = gast.unparse(gtree2)
  if gcode != gcode2:
      raise RuntimeError(gcode, gcode2)

  tree2 = gast.gast_to_ast(gtree)
  gtree3 = gast.ast_to_gast(tree2)
  gcode3 = gast.unparse(gtree3)
  if gcode2 != gcode3:
      raise RuntimeError(gcode2, gcode3)
  gast.dump(gtree3, indent=4, include_attributes=True)



def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
