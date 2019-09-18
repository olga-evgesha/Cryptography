import javax.xml.bind.DatatypeConverter;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricKeyCryptographyExample {
    public static void main(String[] args) throws Exception {
        // Инициализация веторк
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] rnd = new byte[16];
        random.nextBytes(rnd);
        IvParameterSpec ivSpec = new IvParameterSpec(rnd);
        // Создание ключа
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        Key key = keygen.generateKey();
        // CBC
        String text = "It is our very secret string too";
        String transformation = "AES/CBC/PKCS5Padding"; // алгоритм/режим/разбивка (каждый блок данных шифруется отдельно)
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] enc = cipher.doFinal(text.getBytes());
        System.out.println(DatatypeConverter.printHexBinary(enc));
        // Дешифровка
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        String result = new String(cipher.doFinal(enc));
        System.out.println(result);
    }
}
