package RSA;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Administrator on 15-09-2017.
 */
public class KeyUtil {


    public PrivateKey getPrivateKey(String filePath) {
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
            kf = KeyFactory.getInstance("RSA");
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

    public PublicKey getPublicKey(String filePath) {
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
            kf = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
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

    public void generateKeys(String publicKeyPath, String privateKeypath) {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        System.out.println("public key "+publicKey.getEncoded());
        System.out.println("private key "+privateKey.getEncoded());

        String puk = "-----BEGIN PUBLIC KEY-----\n" + new BASE64Encoder().encode(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----";
        String prk = "-----BEGIN PRIVATE KEY-----\n" + new BASE64Encoder().encode(privateKey.getEncoded()) + "\n-----END PRIVATE KEY-----";
        try {
            writeToFile(publicKeyPath, puk.getBytes());
            writeToFile(privateKeypath, prk.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }



}
