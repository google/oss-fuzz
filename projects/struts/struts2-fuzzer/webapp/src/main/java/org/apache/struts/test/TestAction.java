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

package org.apache.struts.test;


import com.opensymphony.xwork2.ActionSupport;

public class TestAction extends ActionSupport {
    private String subject = "World (from Java)";

    public String execute() {
        return ActionSupport.SUCCESS;
    }

    public String getSubject() {
        return this.subject;
    }

    public void setSubject(String subject) {
        if (subject != null) {
            this.subject = subject;
        }
    }
}