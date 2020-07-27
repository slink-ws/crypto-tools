package ws.slink.crypto;

import at.favre.lib.crypto.HKDF;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

@Slf4j
public class Crypto {

    // encode incoming message to hex string
    public static String encode(String message) {
        return Conversion.stringToHexString(message);
    }
    // encode incoming message to hex string
    public static String decode(String message) {
        return Conversion.hexStringToString(message);
    }
    // encrypt incoming message with shared key
    public static String encrypt(String message, byte [] sharedKey) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        byte[] encKey = HKDF.fromHmacSha256().expand(sharedKey, "encKey".getBytes(StandardCharsets.UTF_8), 16);
        byte[] authKey = HKDF.fromHmacSha256().expand(sharedKey, "authKey".getBytes(StandardCharsets.UTF_8), 32); //HMAC-SHA256 key is 32 byte

        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //actually uses PKCS#7
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
            byte[] cipherText = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            SecretKey macKey = new SecretKeySpec(authKey, "HmacSHA256");
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(macKey);
            hmac.update(iv);
            hmac.update(cipherText);

            byte[] mac = hmac.doFinal();

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + 1 + mac.length + cipherText.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put((byte) mac.length);
            byteBuffer.put(mac);
            byteBuffer.put(cipherText);
            byte[] cipherMessage = byteBuffer.array();

            String result = DatatypeConverter.printBase64Binary(cipherMessage);
            return result;
        } catch (NoSuchAlgorithmException e) {
            log.error("encryption error: " + e.getMessage());
        } catch (InvalidKeyException e) {
            log.error("encryption error: " + e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            log.error("encryption error: " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            log.error("encryption error: " + e.getMessage());
        } catch (BadPaddingException e) {
            log.error("encryption error: " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            log.error("encryption error: " + e.getMessage());
        }
        throw new RuntimeException("aes: could not encrypt message");
    }
    // decrypt incoming message with shared key
    public static String decrypt(String message, byte [] sharedKey) {

        byte[] cipherMessage = DatatypeConverter.parseBase64Binary(message);
        ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);

        int ivLength = (byteBuffer.get());
        if (ivLength != 16) { // check input parameter
            throw new IllegalArgumentException("AES: invalid iv length");
        }
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);

        int macLength = (byteBuffer.get());
        if (macLength != 32) { // check input parameter
            throw new IllegalArgumentException("AES: invalid mac length");
        }
        byte[] mac = new byte[macLength];
        byteBuffer.get(mac);

        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        byte[] encKey = HKDF.fromHmacSha256().expand(sharedKey, "encKey".getBytes(StandardCharsets.UTF_8), 16);
        byte[] authKey = HKDF.fromHmacSha256().expand(sharedKey, "authKey".getBytes(StandardCharsets.UTF_8), 32);

        try {
            SecretKey macKey = new SecretKeySpec(authKey, "HmacSHA256");
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(macKey);
            hmac.update(iv);
            hmac.update(cipherText);

            byte[] refMac = hmac.doFinal();

            if (!MessageDigest.isEqual(refMac, mac)) {
                throw new SecurityException("AES: could not authenticate message");
            }

            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
            byte[] plainText = cipher.doFinal(cipherText);

            String result = new String(plainText);
            return result;
        } catch (NoSuchAlgorithmException e) {
            log.error("decryption error: " + e.getMessage());
        } catch (InvalidKeyException e) {
            log.error("decryption error: " + e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            log.error("decryption error: " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            log.error("decryption error: " + e.getMessage());
        } catch (BadPaddingException e) {
            log.error("decryption error: " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            log.error("decryption error: " + e.getMessage());
        }
        throw new RuntimeException("aes: could not decrypt message");
    }

}
