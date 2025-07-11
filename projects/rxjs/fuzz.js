// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////



const { FuzzedDataProvider } = require('@jazzer.js/core');
const { reduce, of, from, Observable, Subject } = require('rxjs');
const { map, filter, take, mergeMap, switchMap, concatMap, distinctUntilChanged, debounceTime, throttleTime, buffer, window } = require('rxjs/operators');

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);

  const arrayLength = provider.consumeIntegralInRange(1, 100);
  const array = Array.from({ length: arrayLength }, () => provider.consumeNumber());

  const source$ = of(...array);

  const result$ = source$.pipe(
    filter((value) => value >= 0),
    map((value) => value * provider.consumeIntegralInRange(1, 10)),
    map((value) => value.toString()),
    map((value) => parseInt(value)),
    take(provider.consumeIntegralInRange(1, 100)),
    reduce((acc, curr) => acc + curr, 0),
    mergeMap((sum) => of(sum, sum + 1)),
    distinctUntilChanged(),
    switchMap((value) => from([value, value + 1])),
    concatMap((value) => from([value, value + 1])),
    debounceTime(provider.consumeIntegralInRange(1, 1000)),
    throttleTime(provider.consumeIntegralInRange(1, 1000)),
    buffer(from([1, 2, 3])),
    window(from([1, 2, 3])),
  );


  const subject$ = new Subject();
  const subscription = result$.subscribe(subject$);


  subject$.next(provider.consumeNumber());


  subscription.unsubscribe();
};
