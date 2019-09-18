import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class KeyAgreementExample {
    public static void main(String[] args) {
        try {
            // 1. Алиса генерирует пару ключей.
            KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            KeyPair aliceKeyPair = generator.generateKeyPair();
            byte[] alicePubKeyEncoded = aliceKeyPair.getPublic().getEncoded();
            // 2. Боб получает открытый ключ Алисы
            KeyFactory bobKeyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEncoded);
            PublicKey alicePubKey = bobKeyFactory.generatePublic(x509KeySpec);
            // Параметры, которые использовала Алиса при генерации ключей
            DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey) alicePubKey).getParams();
            // Создаёт свою пару ключей. Отдаёт свой открытый ключ
            KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
            bobKpairGen.initialize(dhParamFromAlicePubKey);
            KeyPair bobKeyPair = bobKpairGen.generateKeyPair();
            byte[] bobPubKeyEncoded = bobKeyPair.getPublic().getEncoded();
            // 3. Соглашение по протоколу Диффи-Хеллмана (Diffie–Hellman, DH)
            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
            aliceKeyAgree.init(aliceKeyPair.getPrivate());
            // Алиса на основе ключа Боба и своего приватного ключа создаёт общий ключ
            KeyFactory aliceKeyFactory = KeyFactory.getInstance("DH");
            x509KeySpec = new X509EncodedKeySpec(bobPubKeyEncoded);
            PublicKey bobPubKey = aliceKeyFactory.generatePublic(x509KeySpec);
            aliceKeyAgree.doPhase(bobPubKey, true);
            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
            // Боб на основе ключа Алисы и своего приватного создаёт общий ключ
            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
            bobKeyAgree.init(bobKeyPair.getPrivate());
            bobKeyAgree.doPhase(alicePubKey, true);
            byte[] bobSharedSecret = bobKeyAgree.generateSecret();
            SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
            // Общий ключ у Алисы и Боба одинаков
            System.out.println(DatatypeConverter.printHexBinary(aliceSharedSecret));
            System.out.println(DatatypeConverter.printHexBinary(bobSharedSecret));
            System.out.println(Arrays.equals(aliceSharedSecret, bobSharedSecret));
            //Далее Боб и Алиса, используя общий ключ, про который больше никто не знает, обмениваются зашифрованными данными:
            // 4. Боб шифрует сообщение для Алисы
            Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
            byte[] ciphertext = bobCipher.doFinal("Hello, Alice, I am glad to see you".getBytes());
            System.out.println(DatatypeConverter.printHexBinary(ciphertext));
            // Передаёт Алисе параметры, с которыми выполнялась шифровка
            byte[] encodedParamsFromBob = bobCipher.getParameters().getEncoded();
            // 5. Алиса принимает сообщение и расшифровывает его
            AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
            aesParams.init(encodedParamsFromBob);
            Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
            byte[] recovered = aliceCipher.doFinal(ciphertext);
            System.out.println(new String(recovered));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
