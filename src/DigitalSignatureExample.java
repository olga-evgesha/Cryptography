import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.security.*;

public class DigitalSignatureExample {
    public static void main(String[] args) throws Exception {
        // Генерация ключей
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();
        generator.initialize(2048, random);
        KeyPair keyPair = generator.generateKeyPair();
        // Создаем подпись
        Signature dsa = Signature.getInstance("SHA256withRSA");
        dsa.initSign(keyPair.getPrivate());
        // Подписываем данные и шифруем их
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] data = cipher.doFinal("Hello world of cryptography again".getBytes());
        System.out.println(DatatypeConverter.printHexBinary(data));
        dsa.update(data);
        byte[] signature = dsa.sign();
        System.out.println(DatatypeConverter.printHexBinary(signature));
        // Проверяем подпись
        dsa.initVerify(keyPair.getPublic());
        dsa.update(data);
        boolean verifies = dsa.verify(signature);
        System.out.println("Signature is right: " + verifies);
        // Если корректна выводим
        if (verifies) {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] result = cipher.doFinal(data);
            System.out.println(new String(result));
        }
    }
}
