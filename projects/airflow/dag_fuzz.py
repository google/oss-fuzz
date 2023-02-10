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
import colorlog
from datetime import datetime, timedelta
with atheris.instrument_imports():
   import airflow
   from airflow import DAG
   from airflow.exceptions import AirflowException
   from airflow.operators.dummy_operator import DummyOperator
   from airflow.operators.python_operator import PythonOperator

def py_func():
   return

def TestInput(input_bytes):
   fdp = atheris.FuzzedDataProvider(input_bytes)

   default_args = {
      'owner': fdp.ConsumeString(8),
      'depends_on_past': fdp.ConsumeBool(),
      'start_date': airflow.utils.dates.days_ago(fdp.ConsumeIntInRange(1,5)),
      'email': [fdp.ConsumeString(8)],
      'email_on_failure': fdp.ConsumeBool(),
      'email_on_retry': fdp.ConsumeBool(),
      'retries': fdp.ConsumeIntInRange(1,5),
      'retry_delay': timedelta(minutes=fdp.ConsumeIntInRange(1,5)),
   }

   try:
      with DAG(fdp.ConsumeString(8), schedule_interval='@daily', default_args=default_args) as dag:
         dummy_task = DummyOperator(task_id=fdp.ConsumeString(8), retries=fdp.ConsumeIntInRange(1,5))
         python_task = PythonOperator(task_id=fdp.ConsumeString(8), python_callable=py_func)

         dummy_task >> python_task
   except AirflowException:
      pass

def main():
   atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
   atheris.Fuzz()

if __name__ == "__main__":
   main()
