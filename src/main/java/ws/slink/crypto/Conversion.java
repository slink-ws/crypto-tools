package ws.slink.crypto;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class Conversion {

    public static String stringToHexString(String value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value.getBytes()) {
            sb.append(String.format("%x", b));
        }
        return sb.toString();
    }

    public static String hexStringToString(String value) {
        String split = value.replaceAll("..(?!$)", "$0 ");
        List<Byte> chars = Arrays.stream(split.split(" ")).map(s -> (byte)Integer.parseInt(s, 16)).collect(Collectors.toList());
        byte [] result = new byte[chars.size()];
        for (int i = 0; i < chars.size(); i++)
            result[i] = chars.get(i);
        return new String(result);
    }

    public static byte[] hexStringToBytes(String value) {
        return hexStringToString(value).getBytes(StandardCharsets.UTF_8);
    }

}
