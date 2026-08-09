#!/usr/bin/python3
# Copyright 2022 Google LLC
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

import atheris
import sys
try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET
from xml.etree.ElementTree import ParseError
with atheris.instrument_imports():
     from adal.xmlutil import *

XMLTEMPLATE="""
<?xml version="1.0"?>
<%OUTTER%>
    <%INNER% name="%INNERNAME%">
        <%LEAF1%>%LEAF1VALUE1%</%LEAF1%>
        <%LEAF2%>%LEAF2VALUE1%</%LEAF2%>
        <%LEAF3% name="%LEAF3NAME1%" value="%LEAF3VALUE1%"/>
        <%LEAF3% name="%LEAF3NAME4%" value="%LEAF3VALUE4%"/>
    </%INNER%>
    <%INNER% name="%INNERNAME%">
        <%LEAF1%>%LEAF1VALUE2%</rank>
        <%LEAF2%>%LEAF2VALUE2%</year>
        <%LEAF3% name="%LEAF3NAME2%" value="%LEAF3VALUE2%"/>
    </%INNER%>
    <%INNER% name="%INNERNAME%">
        <%LEAF1%>%LEAF1VALUE3%</%LEAF1%>
        <%LEAF2%>%LEAF2VALUE3%</%LEAF2%>
        <%LEAF3% name="%LEAF3NAME3%" value="%LEAF3VALUE3%"/>
    </%INNER%>
</%OUTTER%>
"""

def generate_sample_xml(fdp):
    global XMLTEMPLATE
    xml_string = XMLTEMPLATE

    replace_tag = ["%OUTTER%","%INNER%","%LEAF1%","%LEAF2%","%LEAF3%"]
    replace_value = ["%INNERNAME%",
        "%LEAF1VALUE1%","%LEAF2VALUE1%","%LEAF3NAME1%","%LEAF3VALUE1%",
        "%LEAF1VALUE2%","%LEAF2VALUE2%","%LEAF3NAME2%","%LEAF3VALUE3%",
        "%LEAF1VALUE3%","%LEAF2VALUE3%","%LEAF3NAME2%","%LEAF3VALUE4%",
        "%LEAF3NAME4","%LEAF3VALUE4%"
    ]

    for tag in replace_tag+replace_value:
        xml_string = xml_string.replace(tag,fdp.ConsumeUnicodeNoSurrogates(10))

    return xml_string

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        expand_q_names(fdp.ConsumeString(100))
    except IndexError as e:
        if "Unable to parse XPath string:" not in str(e):
            raise e
    except KeyError:
        return

    try:
        dom = ET.fromstring(generate_sample_xml(fdp))
    except ParseError:
        return

    xpath_find(dom,fdp.ConsumeString(30))
    serialize_node_children(dom)
    is_element_node(dom)
    find_element_text(dom)

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
