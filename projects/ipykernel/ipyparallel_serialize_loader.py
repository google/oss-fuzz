#!/usr/bin/python3
# Copyright 2026 Google LLC
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
"""Load ipyparallel serialization helpers without importing ipyparallel."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
from pathlib import Path


def _serialize_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "ipyparallel_serialize"

    dist = importlib.metadata.distribution("ipyparallel")
    return Path(dist.locate_file("ipyparallel/serialize"))


def _load_serialize_package():
    package_name = "_oss_fuzz_ipyparallel_serialize"
    if package_name in sys.modules:
        return sys.modules[package_name]

    package_dir = _serialize_dir()
    spec = importlib.util.spec_from_file_location(
        package_name,
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load ipyparallel.serialize from {package_dir}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module


_serialize = _load_serialize_package()

deserialize_object = _serialize.deserialize_object
serialize_object = _serialize.serialize_object
unpack_apply_message = _serialize.unpack_apply_message
pack_apply_message = _serialize.pack_apply_message
