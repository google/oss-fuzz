import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.springframework.cloud.context.encrypt.EncryptorFactory;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import java.nio.charset.Charset;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.math.BigInteger;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.cloud.context.encrypt.KeyFormatException;

public class EncryptionIntegrationFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String keyStr = data.consumeString(100);
        String salt = data.consumeString(50);
        if (keyStr.isEmpty() || salt.isEmpty()) {
            return;
        }

        String content = data.consumeRemainingAsString();

        TextEncryptor encryptor;
		try {
            encryptor = new EncryptorFactory(salt).create(keyStr);
        } catch (KeyFormatException e) {
            return;
        }

        String encrypted = encryptor.encrypt(content);
        String decrypted = encryptor.decrypt(encrypted);

		if (!decrypted.equals(content)) {
            throw new FuzzerSecurityIssueHigh("Different result when encrypting & decrypting: " + decrypted + " != " + content);
        }
	}
}