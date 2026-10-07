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
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.ldap.core.AuthenticationSource;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFReader;
import org.springframework.security.ldap.server.UnboundIdContainer;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;

public class BindAuthenticatorFuzzer {
    private static InMemoryDirectoryServer directoryServer;

    public static void fuzzerTearDown() {
        if (directoryServer instanceof InMemoryDirectoryServer) {
            directoryServer.shutDown(true);
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String username = data.consumeString(100);
        String password = data.consumeRemainingAsString();

        if (username.isEmpty() || password.isEmpty() || (username.equals("admin") && password.equals("secret"))) {
            return;
        }

        if (directoryServer instanceof InMemoryDirectoryServer) {
            directoryServer.shutDown(true);
        }

        createInMemoryLdapServer();

        DefaultSpringSecurityContextSource context = new DefaultSpringSecurityContextSource("ldap://localhost:1234/dc=springframework,dc=org");
        context.setUserDn("uid=admin,ou=system");
        context.setPassword("secret");
        context.afterPropertiesSet();

        BindAuthenticator authenticator = new BindAuthenticator(context);
        authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people" });
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        DirContextOperations user = null;

        try {
            user = authenticator.authenticate(token);
        } catch (BadCredentialsException e) {
            // BadCredentialsException is expected here
        } finally {
            if (user != null) {
                throw new FuzzerSecurityIssueHigh("Invalid user `" + username + "` could authenticate");
            }
        }
    }

    private static void createInMemoryLdapServer() {
        String defaultPartitionName = "dc=springframework,dc=org";
        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(defaultPartitionName);
            config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("LDAP", 1234));
            config.setEnforceSingleStructuralObjectClass(false);
            config.setEnforceAttributeSyntaxCompliance(true);
            Entry dc = new Entry(new DN("dc=springframework,dc=org"));
            dc.addAttribute("objectClass", "top", "domain", "extensibleObject");
            dc.addAttribute("dc", "springframework");
            dc.addAttribute("ou", "people");

            Entry ou = new Entry(new DN("ou=people,dc=springframework,dc=org"));
            ou.addAttribute("objectClass", "organizationalUnit");
            ou.addAttribute("ou", "people");

            Entry cn = new Entry(new DN("uid=admin,ou=people,dc=springframework,dc=org"));
            cn.addAttribute("objectClass", "person");
            cn.addAttribute("objectClass", "inetOrgPerson");
            cn.addAttribute("cn", "Adm");
            cn.addAttribute("sn", "In");
            cn.addAttribute("uid", "admin");
            cn.addAttribute("userPassword", "secret");
            directoryServer = new InMemoryDirectoryServer(config);

            directoryServer.add(dc);
            directoryServer.add(ou);
            directoryServer.add(cn);
            directoryServer.startListening();
        } catch (LDAPException e) {
            e.printStackTrace();
        }
    }
} 