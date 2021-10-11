#!/usr/bin/python3

# Copyright 2021 Google LLC
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
import cwltool.main
from hypothesis import given, strategies as st


@given(
    parallel=st.booleans(),
    preserve_entire_environment=st.booleans(),
    _tmpdir=st.one_of(st.just("--rm-tmpdir"), st.just("--leave-tmpdir")),
    _outputs=st.one_of(st.just('--move-outputs'), st.just('--leave-outputs'), st.just('--copy-outputs')),
    print_rdf=st.booleans(),
    _strict=st.one_of(st.just('--strict'), st.just('--non-strict')),
    _doc_cache=st.one_of(st.just('--no-doc-cache'), st.just('--doc-cache')),
    debug=st.booleans(),
    timestamps=st.booleans(),
    enable_dev=st.booleans(),
    enable_ext=st.booleans(),
    _color=st.one_of(st.just('--enable-color'), st.just('--disable-color')),
    _user_provenance=st.one_of(st.just('--enable-user-provenance'), st.just('--disable-user-provenance')),
    _host_provenance=st.one_of(st.just('--enable-host-provenance'), st.just('--disable-host-provenance')),
    orcid=st.from_regex(r"\"\w+\"", fullmatch=True),
    full_name=st.from_regex(r"\"\w+\"", fullmatch=True),
    inp=st.from_regex(r"\"\w+\"", fullmatch=True)
)
@atheris.instrument_func
def test_cwltool_hypothesis(
        parallel,
        preserve_entire_environment,
        _tmpdir,
        _outputs,
        print_rdf,
        _strict,
        _doc_cache,
        debug,
        timestamps,
        enable_dev,
        enable_ext,
        _color,
        _user_provenance,
        _host_provenance,
        orcid,
        full_name,
        inp
):
    args = dict(locals())
    # drop values that are False
    # rename args that do not start with `_` and `st.booleans()` returned `True` from `arg_name` to `--arg-name`
    # replace `_arg: --actual-param` by `--actual-param`
    cmd_args = []
    for k, v in args.items():
        # exclude values that `st.booleans()` returned `False`
        if k in ['input_bytes', 'inp'] or not v:
            continue
        # keys that start with `_` actually contain the argument value (from `st.sampled_from([...])`)
        if k.startswith('_'):
            cmd_args.append(v)
        else:
            # keys that do not start with `_` contain the argument name such as `--arg-name` but as `arg_name`, so we fix it here
            cmd_args.append(f"--{k.replace('_', '-')}")
            # values that are not boolean, are argument values, such as `--orcid $v`, so we include it
            if type(v) != bool:
                cmd_args.append(v)

    try:
        # add the workflow file name as last positional argument
        cmd_args.extend(['echo.cwl', '--inp', inp])
        print(cmd_args)
        cwltool.main.main(argsl=cmd_args)
    except ValueError:
        pass


def main():
    atheris.Setup(sys.argv, atheris.instrument_func(test_cwltool_hypothesis.hypothesis.fuzz_one_input), enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
