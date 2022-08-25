import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

public class InMemoryUserDetailsManagerChangePasswordFuzzer {
    private final static String USERNAME = "admin";
    private final static String PASSWORD = "secret";
    private final static String USER_ROLE = "ADMIN";
    private static final List<GrantedAuthority> AUTHORITIES = AuthorityUtils.createAuthorityList(USER_ROLE);

    private final static int LENGTH_PASSWORD = 500;

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // generating needed objects
        final String generatedPassword01 = data.consumeString(LENGTH_PASSWORD);
        final String generatedPassword02 = data.consumeRemainingAsString();

        // check if the fuzzer generated useful data
        if (generatedPassword01.equals(PASSWORD) || generatedPassword02.equals(PASSWORD)) {
            return;
        }

        // create all the objects needed for fuzzing the InMemoryUserDetailsManager
        final User user = new User(USERNAME, PASSWORD, AUTHORITIES);
        final InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager(user);

        // set the SecurityContext
        // this makes it so that InMemoryUserDetailsManager.changePassword(old, new) never actually checks the old password
        SecurityContextHolder.getContext().setAuthentication(
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, PASSWORD, AUTHORITIES));

        try {
            userDetailsManager.changePassword(generatedPassword01, generatedPassword02);

            // check if the password was successfully changed
            final String finalPassword = userDetailsManager.loadUserByUsername(USERNAME).getPassword();
            if (PASSWORD.equals(finalPassword)) {
                throw new FuzzerSecurityIssueHigh("Password was not changed to '" + finalPassword + "'");
            }
        } catch (UsernameNotFoundException err) {
            throw new FuzzerSecurityIssueLow("The user disappeared from the InMemoryUserDetailsManager");
        } catch (AccessDeniedException problem) {
            // should not be thrown anymore
            problem.printStackTrace();
            throw problem;
        }
    }

    public static void fuzzerTearDown() {
        SecurityContextHolder.clearContext();
    }
}
