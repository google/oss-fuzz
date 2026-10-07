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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;
import com.icegreen.greenmail.user.GreenMailUser;
import com.icegreen.greenmail.user.UserManager;
import com.icegreen.greenmail.user.UserException;


public class UserManagerFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        
        GreenMail greenMail = new GreenMail(ServerSetup.ALL);
        String email = data.consumeString(240);
        String login = data.consumeString(240);
        String pwd = data.consumeRemainingAsString();
        try {
            
            UserManager userManger = greenMail.getUserManager();
            userManger.createUser(email, login, pwd);
            
            GreenMailUser greenMailUser = userManger.getUser(login);

            if (!greenMailUser.getLogin().equals(login)) {
                throw new FuzzerSecurityIssueMedium("User is not created");
            }
            if (!userManger.test(login, pwd)) {
                throw new FuzzerSecurityIssueMedium("Loggin is not possible!");
            }

            userManger.deleteUser(greenMailUser);

        } catch (UserException e) { }
    }
}
