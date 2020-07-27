package ws.slink.crypto.test;

import org.junit.Test;
import ws.slink.crypto.Conversion;

import static org.junit.Assert.assertEquals;

public class ConversionTest {

    private final String TEST_CLEAR_STRING = "test string";
    private final String TEST_HEX_STRING   = "7465737420737472696e67";

    @Test
    public void testStringToHexString() {
        assertEquals(TEST_HEX_STRING, Conversion.stringToHexString(TEST_CLEAR_STRING));
    }

    @Test
    public void hexStringToString() {
        assertEquals(TEST_CLEAR_STRING, Conversion.hexStringToString(TEST_HEX_STRING));
    }

    @Test
    public void hexStringToBytes() {
        assertEquals(TEST_CLEAR_STRING, new String(Conversion.hexStringToBytes(TEST_HEX_STRING)));
    }

}
