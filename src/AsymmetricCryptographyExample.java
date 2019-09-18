import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.security.*;

public class AsymmetricCryptographyExample {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keyPair = generator.generateKeyPair();
        // Шифрование с использование приватного ключа
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] data = cipher.doFinal("Hello world of cryptography".getBytes());
        System.out.println(DatatypeConverter.printHexBinary(data));
        // Дешифровка с использованием публичного
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] result = cipher.doFinal(data);
        System.out.println(new String(result));
    }
}
