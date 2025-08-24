package simple;

import org.junit.Test;
import static org.junit.Assert.*;

// ID = 4825944
public class Test369 {

    // Placeholder Main class for testing
    static class Main {
        public int calc(String[] args) {
            if (args == null || args.length == 0) return -1;
            if (args.length < 3) return -1;

            try {
                int a = Integer.parseInt(args[0]);
                int b = Integer.parseInt(args[1]);
                boolean flag = Boolean.parseBoolean(args[2]);

                if (flag) {
                    return Math.max(a, b);
                } else {
                    return Math.min(a, b);
                }
            } catch (NumberFormatException e) {
                return -1;
            }
        }
    }

    @Test
    public void test_10_01() {
        Main obj = new Main();
        String[] test = new String[] {"", "", ""};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_02() {
        Main obj = new Main();
        String[] test = new String[] {"", "", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_03() {
        Main obj = new Main();
        String[] test = new String[] {"", "0", ""};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_04() {
        Main obj = new Main();
        String[] test = new String[] {"", "0", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_05() {
        Main obj = new Main();
        String[] test = new String[] {"", "1", ""};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_06() {
        Main obj = new Main();
        String[] test = new String[] {"", "1", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_07() {
        Main obj = new Main();
        String[] test = new String[] {"2", "", ""};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_08() {
        Main obj = new Main();
        String[] test = new String[] {"2", "", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_09() {
        Main obj = new Main();
        String[] test = new String[] {"2", "0", ""};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_10() {
        Main obj = new Main();
        String[] test = new String[] {"2", "0", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_11() {
        Main obj = new Main();
        String[] test = new String[] {"2", "1", ""};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_12() {
        Main obj = new Main();
        String[] test = new String[] {"2", "1", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_13() {
        Main obj = new Main();
        String[] test = new String[] {"2", "1", "true"};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_14() {
        Main obj = new Main();
        String[] test = new String[] {"1", "1", "true"};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_15() {
        Main obj = new Main();
        String[] test = new String[] {"1", "", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_16() {
        Main obj = new Main();
        String[] test = new String[] {"1", "0", ""};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_17() {
        Main obj = new Main();
        String[] test = new String[] {"1", "0", "true"};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_18() {
        Main obj = new Main();
        String[] test = new String[] {"1", "1", ""};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_19() {
        Main obj = new Main();
        String[] test = new String[] {"1", "2", ""};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_20() {
        Main obj = new Main();
        String[] test = new String[] {"1", "2", "true"};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_21() {
        Main obj = new Main();
        String[] test = new String[] {"2", "0", "true"};
        int actual = obj.calc(test);
        int expected = 2;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_22() {
        Main obj = new Main();
        String[] test = new String[] {"2", "1", "true"};
        int actual = obj.calc(test);
        int expected = 2;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_23() {
        Main obj = new Main();
        String[] test = new String[] {"3", "0", "true"};
        int actual = obj.calc(test);
        int expected = 3;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_24() {
        Main obj = new Main();
        String[] test = new String[] {"3", "1", "true"};
        int actual = obj.calc(test);
        int expected = 3;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_25() {
        Main obj = new Main();
        String[] test = new String[] {"1", "10", "true"};
        int actual = obj.calc(test);
        int expected = 10;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_26() {
        Main obj = new Main();
        String[] test = new String[] {"1", "100", "true"};
        int actual = obj.calc(test);
        int expected = 100;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_27() {
        Main obj = new Main();
        String[] test = new String[] {"10", "1", "true"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_28() {
        Main obj = new Main();
        String[] test = new String[] {"1", "", ""};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_29() {
        Main obj = new Main();
        String[] test = new String[] {"11", "0", "false"};
        int actual = obj.calc(test);
        int expected = 0;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_30() {
        Main obj = new Main();
        String[] test = new String[] {"-1", "10", "false"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_31() {
        Main obj = new Main();
        String[] test = new String[] {"-1", "0", "false"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_32() {
        Main obj = new Main();
        String[] test = new String[] {"-1", "-10", "false"};
        int actual = obj.calc(test);
        int expected = -10;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_33() {
        Main obj = new Main();
        String[] test = new String[] {"1", "-10", "false"};
        int actual = obj.calc(test);
        int expected = -10;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_34() {
        Main obj = new Main();
        String[] test = new String[] {"-1", "5", "false"};
        int actual = obj.calc(test);
        int expected = -1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_35() {
        Main obj = new Main();
        String[] test = new String[] {"1", "5", "false"};
        int actual = obj.calc(test);
        int expected = 1;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_36() {
        Main obj = new Main();
        String[] test = new String[] {"-6", "0", "false"};
        int actual = obj.calc(test);
        int expected = -6;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_37() {
        Main obj = new Main();
        String[] test = new String[] {"-6", "6", "false"};
        int actual = obj.calc(test);
        int expected = -6;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_38() {
        Main obj = new Main();
        String[] test = new String[] {"-6", "-6", "false"};
        int actual = obj.calc(test);
        int expected = -6;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_39() {
        Main obj = new Main();
        String[] test = new String[] {"0", "6", "false"};
        int actual = obj.calc(test);
        int expected = 0;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_40() {
        Main obj = new Main();
        String[] test = new String[] {"6", "0", "false"};
        int actual = obj.calc(test);
        int expected = 0;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_41() {
        Main obj = new Main();
        String[] test = new String[] {"12", "6", "false"};
        int actual = obj.calc(test);
        int expected = 6;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_42() {
        Main obj = new Main();
        String[] test = new String[] {"12", "12", "false"};
        int actual = obj.calc(test);
        int expected = 12;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_43() {
        Main obj = new Main();
        String[] test = new String[] {"12", "-12", "false"};
        int actual = obj.calc(test);
        int expected = -12;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_44() {
        Main obj = new Main();
        String[] test = new String[] {"-12", "6", "false"};
        int actual = obj.calc(test);
        int expected = -12;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_45() {
        Main obj = new Main();
        String[] test = new String[] {"-12", "-12", "false"};
        int actual = obj.calc(test);
        int expected = -12;
        assertEquals(expected, actual);
    }

    @Test
    public void test_10_46() {
        Main obj = new Main();
        String[] test = new String[] {"0", "0", "false"};
        int actual = obj.calc(test);
        int expected = 0;
        assertEquals(expected, actual);
    }
}
