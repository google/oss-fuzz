#!/bin/bash
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
#
################################################################################

_is_sourced() {
	# https://unix.stackexchange.com/a/215279
	[ "${#FUNCNAME[@]}" -ge 2 ] \
		&& [ "${FUNCNAME[0]}" = '_is_sourced' ] \
		&& [ "${FUNCNAME[1]}" = 'source' ]
}

_main() {
	/etc/init.d/mysql start
	(echo "CREATE USER 'test' IDENTIFIED BY 'test' ;" | mysql) || true
	(echo "GRANT ALL PRIVILEGES ON *.* TO 'test';" | mysql) || true
	(echo "DROP DATABASE test" | mysql --user=test --password=test) || true
	(echo "CREATE DATABASE test" | mysql --user=test --password=test) || true
	exec "$@"
}

if ! _is_sourced; then
	_main "$@"
fi