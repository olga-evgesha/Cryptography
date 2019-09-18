import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificatesExample {
    private X509CertImpl certificate;
    private KeyPair keyPair;

    public static void main(String[] args) throws Exception {
        CertificatesExample example = new CertificatesExample();
//        example.useStandardCertificates();
        example.createCertificates();
    }

    public void useStandardCertificates() throws Exception {
        CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
        certGen.generate(2048);
        PrivateKey privateKey = certGen.getPrivateKey();
        System.out.println(DatatypeConverter.printHexBinary((privateKey.getEncoded())));
        X509Key publicKey = certGen.getPublicKey();
        System.out.println(DatatypeConverter.printHexBinary((publicKey.getEncoded())));
        long validSecs = (long) 365 * 24 * 60 * 60;
        X500Name principal = new X500Name("CN=My Application,O=My Organisation,L=My City,C=DE");
        X509Certificate cert = certGen.getSelfCertificate(principal, validSecs);
        PublicKey publicKeyFromCert = cert.getPublicKey();
        System.out.println(DatatypeConverter.printHexBinary((publicKeyFromCert.getEncoded())));
        System.out.println(publicKeyFromCert.equals(publicKey));
    }

    public void createCertificates() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        keyPair = keyPairGenerator.generateKeyPair();
        Date from = new Date();
        Date to = new Date(from.getTime() + 365 * 1000L * 24L * 60L * 60L);
        CertificateValidity interval = new CertificateValidity(from, to);
        X500Name owner = new X500Name("cn=Unknown");
        BigInteger number = new BigInteger(64, new SecureRandom());
        CertificateSerialNumber serialNumber = new CertificateSerialNumber(number);
        AlgorithmId algorithmId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        CertificateAlgorithmId certificateAlgorithmId = new CertificateAlgorithmId(algorithmId);
        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, serialNumber);
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, certificateAlgorithmId);
        certificate = new X509CertImpl(info);
        certificate.sign(keyPair.getPrivate(), "SHA256withRSA");
        try {
            certificate.verify(keyPair.getPublic());
            System.out.println("Сертификат верифицирован");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public X509CertImpl getCertificate() {
        return certificate;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }
}
