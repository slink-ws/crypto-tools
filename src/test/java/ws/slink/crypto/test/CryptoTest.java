package ws.slink.crypto.test;

import org.junit.Test;
import ws.slink.crypto.Conversion;
import ws.slink.crypto.Crypto;

import static org.junit.Assert.assertEquals;

public class CryptoTest {

    private final String TEST_SHARED_KEY = "test shared key";
    private final String TEST_MESSAGE = "test message (clear text)";

    @Test
    public void testEncryptDecrypt() {
        byte [] sharedKey = Conversion.hexStringToBytes(Conversion.stringToHexString(TEST_SHARED_KEY));
        assertEquals(TEST_MESSAGE, Crypto.decrypt(Crypto.encrypt(TEST_MESSAGE, sharedKey), sharedKey));
    }

    @Test
    public void testEncodeDecode() {
        assertEquals(TEST_MESSAGE, Crypto.decode(Crypto.encode(TEST_MESSAGE)));
    }

}
