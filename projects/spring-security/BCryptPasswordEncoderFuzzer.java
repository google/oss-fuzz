import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptPasswordEncoderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        BCryptPasswordEncoder.BCryptVersion bCryptVersion = data.pickValue(new BCryptPasswordEncoder.BCryptVersion[]
                {BCryptPasswordEncoder.BCryptVersion.$2A, BCryptPasswordEncoder.BCryptVersion.$2B, BCryptPasswordEncoder.BCryptVersion.$2Y});

        BCryptPasswordEncoder encoder;
        try {
            if (data.consumeBoolean()) {
                encoder = new BCryptPasswordEncoder(bCryptVersion);
            } else {
                // using MAX_LOG_ROUNDS will slow down the fuzz test
                encoder = new BCryptPasswordEncoder(bCryptVersion, data.consumeInt(-1, 10));
            }
        } catch (IllegalArgumentException ignored) {
            return;
        }

        String password = data.consumeRemainingAsString();
        if (password.isEmpty()) {
            return;
        }

        String result = encoder.encode(password);
        if (!encoder.matches(password, result)) {
            throw new FuzzerSecurityIssueHigh("Password `" + password + "` does not match encoded one `" + result + "`");
        }
    }
}
