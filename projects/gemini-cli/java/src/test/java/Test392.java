package simple;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.Test;

public class Test392 {
    // Placeholder RomanNumeralUtils class
    static class RomanNumeralUtils {
        public static int fromRoman(String roman) {
            if (roman == null || roman.trim().isEmpty()) {
                return -1;
            }

            java.util.Map<Character, Integer> romanMap = new java.util.HashMap<>();
            romanMap.put('I', 1);
            romanMap.put('V', 5);
            romanMap.put('X', 10);
            romanMap.put('L', 50);
            romanMap.put('C', 100);
            romanMap.put('D', 500);
            romanMap.put('M', 1000);

            int total = 0;
            int prevValue = 0;

            for (int i = roman.length() - 1; i >= 0; i--) {
                char c = roman.charAt(i);
                Integer value = romanMap.get(c);

                if (value == null) {
                    return -1; // Invalid character
                }

                if (value < prevValue) {
                    total -= value;
                } else {
                    total += value;
                }
                prevValue = value;
            }

            return total;
        }
    }

    @Test
    public void shouldBeValid() {
        int result = RomanNumeralUtils.fromRoman("MCMXC");
        assertNotEquals(-1, result, "MCMXC should be a valid Roman numeral");
        assertEquals(1990, result, "MCMXC should equal 1990");
    }
}
