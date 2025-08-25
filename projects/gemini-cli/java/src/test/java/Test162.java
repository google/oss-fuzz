package simple;

import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

public class Test162 {

    // Placeholder RegexCheck class for IP validation
    static class RegexCheck {
        public static boolean matches(String pattern, String input) {
            if (input == null) return false;

            // Simple IP address validation
            String ipPattern = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            return input.matches(ipPattern);
        }
    }

    public static String[] valid = {
        "1.1.1.1",
        "255.255.255.255",
        "192.168.1.1",
        "10.10.1.10",
        "132.254.111.10",
        "26.1.2.3",
        "0.0.0.0",
        "127.0.0.1"
    };

    public static String[] invalid = {
        "",
        "abc.def.ghi.jkl",
        "123.456.789.012",
        "123.045.067.089",
        "192.168.1.300",
        "127.1.1.0.",
        "127.1.1.0.",
        "127.1.1.0.",
        "127.1.1.0.",
        "1.2.3.4.5"
    };

    @Test
    public void test0() {
        for (String s : valid) {
            assertTrue(s + " should be valid", RegexCheck.matches("1.1.1.1", s));
        }
    }

    @Test
    public void test1() {
        for (String s : invalid) {
            assertFalse(s + " should be invalid!", RegexCheck.matches("1.1.1.1", s));
        }
    }
}
