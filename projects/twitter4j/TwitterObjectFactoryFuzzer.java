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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import twitter4j.TwitterException;
import twitter4j.TwitterObjectFactory;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-1
// Heuristic name: jvm-autofuzz-heuristics-1
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.User createUser(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.UserList createUserList(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.Place createPlace(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.DirectMessage createDirectMessage(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.SavedSearch createSavedSearch(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static java.lang.Object createObject(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.AccountTotals createAccountTotals(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.Location createLocation(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.IDs createIDs(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.Relationship createRelationship(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.Trend createTrend(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.Trends createTrends(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static java.util.Map createRateLimitStatus(java.lang.String) throws twitter4j.TwitterException
// Target method: [twitter4j.TwitterObjectFactory] public static twitter4j.v1.OEmbed createOEmbed(java.lang.String) throws twitter4j.TwitterException
public class TwitterObjectFactoryFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      switch (data.consumeInt(1, 14)) {
        case 1:
          TwitterObjectFactory.createUser(data.consumeRemainingAsString());
          break;
        case 2:
          TwitterObjectFactory.createUserList(data.consumeRemainingAsString());
          break;
        case 3:
          TwitterObjectFactory.createPlace(data.consumeRemainingAsString());
          break;
        case 4:
          TwitterObjectFactory.createDirectMessage(data.consumeRemainingAsString());
          break;
        case 5:
          TwitterObjectFactory.createSavedSearch(data.consumeRemainingAsString());
          break;
        case 6:
          TwitterObjectFactory.createObject(data.consumeRemainingAsString());
          break;
        case 7:
          TwitterObjectFactory.createAccountTotals(data.consumeRemainingAsString());
          break;
        case 8:
          TwitterObjectFactory.createLocation(data.consumeRemainingAsString());
          break;
        case 9:
          TwitterObjectFactory.createIDs(data.consumeRemainingAsString());
          break;
        case 10:
          TwitterObjectFactory.createRelationship(data.consumeRemainingAsString());
          break;
        case 11:
          TwitterObjectFactory.createTrend(data.consumeRemainingAsString());
          break;
        case 12:
          TwitterObjectFactory.createTrends(data.consumeRemainingAsString());
          break;
        case 13:
          TwitterObjectFactory.createRateLimitStatus(data.consumeRemainingAsString());
          break;
        case 14:
          TwitterObjectFactory.createOEmbed(data.consumeRemainingAsString());
          break;
      }
    } catch (TwitterException e1) {
      // Known exception
    }
  }
}
