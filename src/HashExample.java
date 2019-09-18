import javax.xml.bind.DatatypeConverter;
import java.security.*;

public class HashExample {
    public static void main(String[] args) {
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA-512"); //MD5
            byte[] input = "It is our very secret string".getBytes();
            // Соль
//            byte[] salt = new byte[16];
//            SecureRandom.getInstanceStrong().nextBytes(salt);
//            digester.update(salt);
            byte[] digest = digester.digest(input);
            System.out.println(DatatypeConverter.printHexBinary(digest));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
