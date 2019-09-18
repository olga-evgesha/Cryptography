import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class KeyStoreExample {
    public static void main(String[] args) throws Exception {
        CertificatesExample example = new CertificatesExample();
        example.createCertificates();

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        String alias = "EntityAlias";
        Certificate[] chain = {example.getCertificate()};
        keyStore.setKeyEntry(alias, example.getKeyPair().getPrivate(), "keyPassword".toCharArray(), chain);
        // Загрузка содержимого (Private Key + Certificate)
        Key key = keyStore.getKey(alias, "keyPassword".toCharArray());
        Certificate[] certificateChain = keyStore.getCertificateChain(alias);
        // Сохранение KeyStore на диск
        File file = File.createTempFile("security_", ".ks", new File("Cryptography/resource"));
        try (FileOutputStream fos = new FileOutputStream(file)) {
            keyStore.store(fos, "keyStorePassword".toCharArray());
        }
    }
}
