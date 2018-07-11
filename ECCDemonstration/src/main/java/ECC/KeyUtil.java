package ECC;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyUtil {
    public void generateKeys(String publicKeyPath, String privateKeypath) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException {
        /*ECCurve curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
        ECParameterSpec ecSpec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n*/
        KeyPairGenerator g = (KeyPairGenerator) KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");

        g.initialize(parameterSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();

        KeyFactory fact = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        PublicKey publicKey = fact.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
        PrivateKey privateKey = fact.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()));
        //System.out.println(publicKey.getFormat());

        System.out.println(publicKey);
        //System.out.println(privateKey.getFormat());

        //System.out.println(privateKey);

        //gk = new GenerateKeys(256);

        //System.out.println("KeyPair/publicKey "+ publicKey.getEncoded());
        //System.out.println("KeyPair/privateKey "+ privateKey.getEncoded());
        String puk = "-----BEGIN PUBLIC KEY-----\n" + new BASE64Encoder().encode(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----";
        String prk = "-----BEGIN PRIVATE KEY-----\n" + new BASE64Encoder().encode(privateKey.getEncoded()) + "\n-----END PRIVATE KEY-----";

        //System.out.println(puk);
        writeToFile(publicKeyPath, puk.getBytes());
        writeToFile(privateKeypath, prk.getBytes());

        /*StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new PemObject("PUBLIC KEY",publicKey.getEncoded()));
        pemWriter.flush();
        pemWriter.close();
        System.out.println(writer.toString());
        System.out.println(writer.toString().equals(puk));*/
    }


    public static void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public PublicKey getPublicKey(String filePath){
        String publicInBase64 = null;
        try {
            publicInBase64 = new String(Files.readAllBytes(new File(filePath).toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        String publicKeyPEM = publicInBase64.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("\n-----END PUBLIC KEY-----", "");


        byte[] encoded = new byte[0];
        try {
            encoded = new BASE64Decoder().decodeBuffer(publicKeyPEM);
        } catch (IOException e) {
            e.printStackTrace();
        }

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        PublicKey publicKey = null;
        try {
            publicKey = kf.generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public PrivateKey getPrivateKey(String filePath){

        String privateinBase64 = null;
        try {
            privateinBase64 = new String(Files.readAllBytes(new File(filePath).toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        String privKeyPEM = privateinBase64.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privKeyPEM = privKeyPEM.replace("\n-----END PRIVATE KEY-----", "");
        byte[] encoded = new byte[0];
        try {
            encoded = new BASE64Decoder().decodeBuffer(privKeyPEM);
        } catch (IOException e) {
            e.printStackTrace();
        }
        // PKCS8 decode the encoded RSA private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        PrivateKey privKey = null;
        try {
            privKey = kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privKey;

    }


    public static KeyPair generateECKeys() throws Exception {

            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    "ECDH", new BouncyCastleProvider());

            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;

    }

    public void createKeys(String pubKeyPath, String priKeyPath) throws Exception {

        KeyPair keyPair = generateECKeys();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String puk = "-----BEGIN PUBLIC KEY-----\n" + new BASE64Encoder().encode(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----";
        String prk = "-----BEGIN PRIVATE KEY-----\n" + new BASE64Encoder().encode(privateKey.getEncoded()) + "\n-----END PRIVATE KEY-----";

        writeToFile(pubKeyPath, puk.getBytes());
        writeToFile(priKeyPath, prk.getBytes());


    }
}
