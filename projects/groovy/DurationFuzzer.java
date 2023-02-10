// Copyright 2022 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import groovy.time.*;

public class DurationFuzzer {

	int years[] = null;
	int months[] = null;
	int days[] = null;
	int hours[] = null;
	int minutes[] = null;
	int seconds[] = null;
	int millis[] = null;

	public DurationFuzzer(FuzzedDataProvider data) {
		years=new int[] { data.consumeInt(), data.consumeInt() };
		months=new int[] { data.consumeInt(), data.consumeInt() };
		days=new int[] { data.consumeInt(), data.consumeInt() };
		hours=new int[] { data.consumeInt(), data.consumeInt() };
		minutes=new int[] { data.consumeInt(), data.consumeInt() };
		seconds=new int[] { data.consumeInt(), data.consumeInt() };
		millis=new int[] { data.consumeInt(), data.consumeInt() };
	}
	
	void runTest(BaseDuration duration1, BaseDuration duration2) {
		duration1.getAgo();
		duration1.compareTo(duration2);
		duration1.getHours();
		duration1.getMillis();
		duration1.getMinutes();
		duration1.getMonths();
		duration1.getSeconds();
		duration1.getYears();
		duration1.toString();
		duration1.getFrom();
		duration1.getFrom().getNow();
		duration1.getFrom().getToday();
		duration1.toMilliseconds();
	}

	void runTest(Duration duration1, Duration duration2) {
		runTest((BaseDuration)duration1, duration2);
		duration1.minus(duration2);
		duration1.plus(duration2);
	}
	void runTest(TimeDuration duration1, TimeDuration duration2) {
		runTest((BaseDuration)duration1, duration2);
		duration1.minus(duration2);
		duration1.plus(duration2);
	}
	void runTest(DatumDependentDuration duration1, DatumDependentDuration duration2) {
		runTest((BaseDuration)duration1, duration2);
		duration1.minus(duration2);
		duration1.plus(duration2);
	}
	void runTest(DatumDependentDuration duration1, TimeDatumDependentDuration duration2) {
		runTest((BaseDuration)duration1, duration2);
		duration1.plus(duration2);
	}

	void runTest(FuzzedDataProvider data) {

		runTest(new Duration(days[0], hours[0], minutes[0], seconds[0], millis[0]), new Duration(days[1], hours[1], minutes[1], seconds[1], millis[1]));
		runTest(new TimeDuration(days[0], hours[0], minutes[0], seconds[0], millis[0]), new TimeDuration(days[1], hours[1], minutes[1], seconds[1], millis[1]));
		runTest(new DatumDependentDuration(years[0], months[0],days[0], hours[0], minutes[0], seconds[0], millis[0]), new TimeDuration(days[1], hours[1], minutes[1], seconds[1], millis[1]));
		runTest(new DatumDependentDuration(years[0], months[0],days[0], hours[0], minutes[0], seconds[0], millis[0]), new TimeDatumDependentDuration(years[1], months[1], days[1], hours[1], minutes[1], seconds[1], millis[1]));

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		DurationFuzzer testClosure = new DurationFuzzer(data);
		testClosure.runTest(data);
	}
}
