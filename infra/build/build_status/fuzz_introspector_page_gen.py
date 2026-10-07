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
"""Logic to create Fuzz Introspector overview page."""
import json

from urllib.request import urlopen
from bs4 import BeautifulSoup

TABLE_HEAD = """<table id="mainTable">
<thead>
            <tr>
      <th title="Fuzzer key. Usually fuzzer executable file">
       Project Report
      </th>
      <th title="Number of fuzz targets for the project.">
       Fuzz target count
      </th>
      <th title="Percentage of code statially reachable from the fuzzers.">
       Code statically reached
      </th>
      <th title="Percentage of code currently covered at runtime.">
       Code covered at runtime
      </th>
     </tr>
    </thead>
<tbody>"""

TABLE_END = """</tbody>
</table>"""

FUZZ_INTROSPECTOR_HTML_TOP = """<html>
<head>
	<style>
		body {
			background: #EBEDEE;
			font-family: "Roboto", sans-serif;
			margin: 0px;
		}
		.main-div {
			padding: 20px;			
		}
		.table-wrapper {
			background: white;
			height: calc(100% - 190px);
			padding: 40px
		}
		.top-navbar {
			height: 70px;
			background:  #222;
			display: flex;
			position: relative;
			color: white;
			align-items: center;
			/*justify-content: center;*/
			padding-left: 20px;
		}
		thead {
			background: #393f43;
			color: white;
		}
		input[type=search] {
			min-height: 38.58px;
		}
		#mainTable_filter {
			margin-bottom: 5px;
		}
		table.dataTable.cell-border tbody th, table.dataTable.cell-border tbody td {
			border:  none!important;
			max-width:  300px;
			word-wrap: break-word;
			font-size:  .8rem;
			font-weight:  700;
		}
		table.dataTable.stripe tbody tr.odd, table tbody tr.odd {
			background: #fafafa !important;
		}
		table.dataTable tbody th, table.dataTable tbody td {
			font-size: .9rem !important;
			border-top: 1px solid #eee !important;
			border-right: 1px solid #eee !important;
			padding: 0.8em !important;
		}
		table.dataTable tbody tr.odd:hover,
		table.dataTable tbody tr.even:hover {
			background: #d6e9f8!important;
		}
		.dataTables_filter {
			float:  left!important;
			text-align: left!important;
			margin-left:  20px;
		}
		.dataTables_paginate.paging_simple_numbers {
			float: left!important;
		}
		.dataTables_wrapper .dataTables_info {
			float: none!important;
		}
		.dataTables_wrapper .dataTables_length, .dataTables_wrapper .dataTables_filter, .dataTables_wrapper .dataTables_info, .dataTables_wrapper .dataTables_processing, .dataTables_wrapper .dataTables_paginate {
			color: #adadad;
			font-size: .95rem;
		}
		.dataTables_wrapper .dataTables_paginate .paginate_button {
			color: #8a8a8a!important;
			padding: 0!important;
			background: none !important;
			border: none !important;
		}
	</style>
</head>
<body>
	<script crossorigin="anonymous" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.datatables.net/1.10.25/js/jquery.dataTables.min.js"></script>
  <link href="https://cdn.datatables.net/1.10.25/css/jquery.dataTables.min.css" rel="stylesheet"/>

  <div class="top-navbar">
   <div class="top-navbar-title-wrapper">
    <div class="top-navbar-title" style="margin-bottom: 10px; font-size:25px">
      Fuzzer introspection of OSS-Fuzz projects
    </div>
    <div style="margin:0; font-size: 10px">
     For issues and ideas:
     <a href="https://github.com/ossf/fuzz-introspector/issues" style="color:#FFFFFF;">
      https://github.com/ossf/fuzz-introspector/issues
     </a>
    </div>
   </div>
  </div>
  <div class="main-div">
  	<div>
      <b>Fuzz Introspector documentation:</b><a href="https://fuzz-introspector.readthedocs.io/en/latest/">https://fuzz-introspector.readthedocs.io/en/latest/</a>
      <br>
      <b>Fuzz Introspector repository:</b><a href="https://github.com/ossf/fuzz-introspector">https://github.com/ossf/fuzz-introspector</a>
  	</div>
	<div class="table-wrapper">"""

FUZZ_INTROSPECTOR_HTML_BOTTOM = """</div>
</div>
	<script>
		$(document).ready( function () {
		  // Get number of rows in this table
		  var rowCount = $('#mainTable tr').length;
		  var sortByColumn = $('#mainTable').data('sort-by-column');
		  var sortOrder = $('#mainTable').data('sort-order');
		  

		  var bPaginate;
		  var bLengthChange;
		  var bInfo;
		  var bFilter;

		  /*if(rowCount<6) {
		    bFilter = false;
		  } else {
		    bFilter = true;
		  }*/
		    bFilter = true;   
		    bPaginate = true;
		    bLengthChange = true;
		    bInfo = true;

		  var tableConfig = {'bPaginate': bPaginate,
		                      'bLengthChange': bLengthChange,
		                      'bInfo': bInfo,
		                      'bFilter': bFilter,
		                      'pageLength': 1000,
		                      'autoWidth': false,
		                      /*dom:            "Bfrtip",*/
		                      paging: true, 
		                      scrollCollapse: true,
		                      buttons:        [ {
		                        extend: 'colvis',
		                        text: "Columns"
		                        },
		                        {
		                          extend: "pageLength",
		                          text: "Rows"
		                        }],
		                      fixedColumns:   {
		                          left: 2
		                      }
		                    }
		  var language = {"lengthMenu": "_MENU_ per page",
		                  "searchPlaceholder": "Search table",
		                  "search": "_INPUT_"}
		  tableConfig.language = language;
		    $('#mainTable').DataTable(tableConfig);
} );
</script>
</body>
</html>"""


def refine_percentage_string(percentage_string):
  """Shortens a srting to 4 characters and prepends zeros if necessary.
  We need to prepend the zero to make sorting in the final table accurrate.
  """
  percentage_string = percentage_string.replace("%", "")
  if len(percentage_string.split(".")[0]) == 1:
    percentage_string = "0" + percentage_string

  if len(percentage_string) > 5:
    percentage_string = percentage_string[:5]

  # Check if the percentage is withing range of [0.0 : 100.0]
  # Some old reports from 2022 have deprecated data, which we do not want to
  # display.
  float_val = float(percentage_string)
  if float_val < 0.0 or float_val > 100.0:
    # Raise exception to make the code display '-' elements.
    raise Exception('Out of range numbers')

  return percentage_string + "%"


def fetch_fuzz_introspector_summary(report_url):
  """Given a URL to an introspector report, returns a dictionary with data
  from the report. This includes, fuzzer count, reachability and code
  coverage.
  """
  # Extract json summary file.
  summary_url = report_url.replace('fuzz_report.html', 'summary.json')
  response = urlopen(summary_url)
  json_data = json.loads(response.read())

  # 1) Extract fuzzer count. This corresponds to all but two elements at the
  # top level of the dictionary.
  fuzzer_count = len(json_data) - 2

  # 2) Extract reachability count.
  reached_stats = "0.0%"
  if 'MergedProjectProfile' in json_data:
    if 'stats' in json_data['MergedProjectProfile']:
      merged_profile = json_data['MergedProjectProfile']
      reached_stats = merged_profile['stats']['reached-complexity-percentage']

  reached_stats = refine_percentage_string(str(reached_stats))

  # Extract code coverage stats.
  # Momentarily, we will get this from the HTML page because it's not yet
  # in the summary.json. This will change in the near future, but in the
  # spirit of time we keep it like this for now.
  fuzz_report_html = urlopen(report_url).read()
  soup = BeautifulSoup(fuzz_report_html, 'html.parser')
  target_divs = soup.findAll('text', {'class': 'percentage'})

  # The code coverage is the third instance of this text class.
  raw_code_coverage = target_divs[2].string.strip()
  code_coverage = refine_percentage_string(raw_code_coverage)

  return {
      'fuzzer_count': fuzzer_count,
      'project_complexity_reached': reached_stats,
      'code_coverage': code_coverage
  }


def get_fuzzer_introspector_project_summary(report_url):
  """Return dictionary containing summary of fuzz introspector project."""
  try:
    results_dict = fetch_fuzz_introspector_summary(report_url)
  except Exception:  # pylint: disable=broad-except
    results_dict = {
        'fuzzer_count': '-',
        'project_complexity_reached': '-',
        'code_coverage': '-'
    }
  return results_dict


def get_fuzz_introspector_row(project, report_url):
  """Creates a single row in the Fuzz Introspector HTML table."""
  project_summary = get_fuzzer_introspector_project_summary(report_url)
  return ("<tr>"
          f"<td><a href='{report_url}'>{project}</a></td>"
          f"<td>{project_summary['fuzzer_count']}</td>"
          f"<td>{project_summary['project_complexity_reached']}</td>"
          f"<td>{project_summary['code_coverage']}</td>"
          "</tr>\n")


def create_introspector_overview_table(fuzz_introspector_index):
  """Creates a HTML table with Fuzz Introspector summary for each project."""
  all_rows = ""
  for project_name in fuzz_introspector_index:
    report_url = fuzz_introspector_index[project_name]
    all_rows += get_fuzz_introspector_row(project_name, report_url)
  return TABLE_HEAD + all_rows + TABLE_END


def get_fuzz_introspector_html_page(fuzz_introspector_index):
  """Creates a HTML page as a string displaying Fuzz Introspector overview."""
  html_table = create_introspector_overview_table(fuzz_introspector_index)
  return (FUZZ_INTROSPECTOR_HTML_TOP + html_table +
          FUZZ_INTROSPECTOR_HTML_BOTTOM)
