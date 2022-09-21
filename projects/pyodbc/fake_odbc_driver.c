/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/* Fake odbc driver that simply returns 0 on every call and has no side effects */

#include <sql.h>
#include <sqlext.h>

SQLRETURN SQLAllocHandle(SQLSMALLINT a1, SQLHANDLE a2, SQLHANDLE *a3) {
  return 0;
}

SQLRETURN
SQLDriverConnect(SQLHDBC ConnectionHandle, SQLHWND WindowHandle,
                 SQLCHAR *InConnectionString, SQLSMALLINT StringLength1,
                 SQLCHAR *OutConnectionString, SQLSMALLINT BufferLength,
                 SQLSMALLINT *StringLength2Ptr, SQLUSMALLINT DriverCompletion) {
  return 0;
}

SQLRETURN SQLSetConnectAttr(SQLHDBC ConnectionHandle, SQLINTEGER Attribute,
                            SQLPOINTER ValuePtr, SQLINTEGER StringLength) {
  return 0;
}

SQLRETURN SQL_API SQLExecDirectW(SQLHSTMT hstmt, SQLWCHAR *szSqlStr,
                                 SQLINTEGER cbSqlStr) {
  return 0;
}

SQLRETURN SQL_API SQLRowCount(SQLHSTMT StatementHandle, SQLLEN *RowCount) {
  return 0;
}

SQLRETURN SQL_API SQLNumResultCols(SQLHSTMT StatementHandle,
                                   SQLSMALLINT *ColumnCount) {
  return 0;
}
