#!/usr/bin/python3.9

import atheris
import re
import sys
import typing
from ast import Assign, Call, Constant, Expr, fix_missing_locations, For, \
    Load, Module, Name, stmt, Store, unparse
from random import choice

with atheris.instrument_imports():
    from space_tracer.main import TraceRunner, replace_input


class CodeContext:
    def __init__(self, data: typing.Iterator[bytes]):
        self.data = data
        self.parent = Module(body=[], type_ignores=[])
        self.local_names = []

    def generate_source(self) -> str:
        for statement in self.generate_statements():
            self.parent.body.append(statement)
        # noinspection PyTypeChecker
        fix_missing_locations(self.parent)
        # noinspection PyTypeChecker
        return unparse(self.parent)

    def generate_ints(self,
                      stop: int = 256,
                      start: int = 0) -> typing.Iterator[int]:
        assert stop - start <= 256
        for value in self.data:
            yield int(value) % (stop - start) + start

    def generate_names(self) -> typing.Iterator[str]:
        for value in self.data:
            yield f'x{value}'

    def generate_statements(self) -> typing.Iterator[stmt]:
        generators = [self.generate_assignments,
                      self.generate_prints,
                      self.generate_for_loops]
        for statement_type in self.generate_ints(3):
            generator = generators[statement_type]
            for statement in generator():
                yield statement
                break

    def generate_assignments(self) -> typing.Iterator[stmt]:
        for name, value in zip(self.generate_names(), self.generate_ints()):
            self.local_names.append(name)
            yield Assign(targets=[Name(id=name, ctx=Store())],
                         value=Constant(value=value))

    def generate_prints(self) -> typing.Iterator[stmt]:
        for scope_choice in self.generate_ints(100):
            if self.local_names:
                name = choice(self.local_names)
            else:
                name = 'x'
            if scope_choice == 0:
                for name in self.generate_names():
                    break
            yield Expr(value=Call(func=Name(id='print', ctx=Load()),
                                  args=[Name(id=name, ctx=Load())], keywords=[]))

    def generate_for_loops(self) -> typing.Iterator[stmt]:
        for iter_name, loop_count, child_count in zip(self.generate_names(),
                                                      self.generate_ints(10),
                                                      self.generate_ints(10)):
            children = [statement
                        for (statement, _) in zip(self.generate_statements(),
                                                  range(child_count))]
            yield For(target=Name(id=iter_name, ctx=Store()),
                      iter=Call(func=Name(id='range', ctx=Load()),
                                args=[Constant(value=loop_count)],
                                keywords=[]),
                      body=children,
                      orelse=[])

def TestOneInput(data):
    """ This gets called over and over with a random bytes object.

    To see the options, run `python fuzz.py -h`. Some options are ignored, like
    `--dict` and `--regression`.
    """
    context = CodeContext(iter(data))
    source = context.generate_source()

    runner = TraceRunner()
    with replace_input(source):
        report = runner.trace_command(['space_tracer',
                                       '--live',
                                       '--trace_offset=1000000',
                                       '-'])
    trimmed_report = re.sub(r'\s*\|\s*$', '', report, flags=re.MULTILINE)
    if source != trimmed_report:
        with replace_input(source):
            report2 = runner.trace_command(['space_tracer',
                                            '--live',
                                            '-'])
        print("### Source ###")
        print(source)
        print()
        print("### Report ###")
        print(report2)
        raise RuntimeError("Source and report differ.")



atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
