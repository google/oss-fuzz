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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import java.net.InetAddress;

import org.apache.juli.logging.LogFactory;
import org.apache.catalina.realm.JNDIRealm;
import org.apache.catalina.realm.GenericPrincipal;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFException;

public class JNDIRealmFuzzer {
    static InMemoryDirectoryServer ldapServer;
    static String username = "admin";
    static String credentials = "password";
    static int poolSize = 1;

    public static class JNDIRW extends JNDIRealm { // JNDIRealm wrapper, because containerLog is protected in JNDIRealm
        public JNDIRW () {
            this.containerLog = LogFactory.getLog(JNDIRealmFuzzer.class);
        }
    }

    public static void fuzzerTearDown() {
        ldapServer.shutDown(true);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        credentials = data.consumeRemainingAsString();
       
        if (username.isEmpty() || credentials.isEmpty() || (username.equals("admin") && credentials.equals("password"))) {
            return;
        }

        if (ldapServer instanceof InMemoryDirectoryServer) {
            ldapServer.shutDown(true);
        }

        try {
            createLDAP();
        } catch (Exception e) {
            throw new FuzzerSecurityIssueHigh("create LDAP error");
        }

        JNDIRW realm = new JNDIRW();

        realm.setConnectionURL("ldap://localhost:" + ldapServer.getListenPort());
        realm.setUserPattern("cn={0},ou=people,dc=example,dc=com");
        realm.setUserSearch(null);
        realm.setUserBase(null);
        realm.setRoleSearch("member=cn={1},ou=people,dc=example,dc=com");
        realm.setRoleBase("ou=people,dc=example,dc=com"); 
        realm.setUserRoleAttribute("cn");
        realm.setRoleName("cn");
        realm.setRoleNested(true);
        realm.setConnectionPoolSize(poolSize);

        for (int i = 0; i < poolSize; i++) {
            GenericPrincipal p = null;
            try {
                p = (GenericPrincipal) realm.authenticate(username, credentials);   
            } catch (Exception e) { 
            } finally {
                if (p != null) { 
                    throw new FuzzerSecurityIssueHigh("Invalid user `" + username + "` could authenticate");
                }    
            }
        }
    }

    public static void createLDAP() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        InetAddress localhost = InetAddress.getByName("localhost");
        InMemoryListenerConfig listenerConfig = new InMemoryListenerConfig("localListener", localhost, 0, null, null, null);
        
        config.setListenerConfigs(listenerConfig);
        config.setEnforceSingleStructuralObjectClass(false);
        config.setEnforceAttributeSyntaxCompliance(true);
        ldapServer = new InMemoryDirectoryServer(config);
        ldapServer.startListening();

        try (LDAPConnection conn =  ldapServer.getConnection()) {
            AddRequest addBase = new AddRequest(
                    "dn: dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: domain",
                    "dc: example");
            LDAPResult result = conn.processOperation(addBase);
            assert ResultCode.SUCCESS == result.getResultCode();

            AddRequest addPeople = new AddRequest(
                    "dn: ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: organizationalUnit");
            result = conn.processOperation(addPeople);
            assert ResultCode.SUCCESS == result.getResultCode();

            AddRequest addUserAdmin = new AddRequest(
                    "dn: cn=admin,ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: person",
                    "objectClass: organizationalPerson",
                    "cn: admin",
                    "sn: Admin",
                    "userPassword: password");
            result = conn.processOperation(addUserAdmin);
            assert ResultCode.SUCCESS == result.getResultCode();
        } catch (LDIFException e) {
            e.printStackTrace();
        }       
    }
}
