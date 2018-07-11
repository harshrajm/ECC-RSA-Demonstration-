package RSA;

import ECC.KeyUtil;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;

/**
 * Created by Administrator on 18-09-2017.
 */
public class EncDcrpt {

    public String encrypt(PublicKey publicKey, String textToEnc) throws InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64String(cipher.doFinal(textToEnc.getBytes("UTF-8")));
    }

    public String decrypt(PrivateKey privateKey, String strToDecode) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.decodeBase64(strToDecode)), "UTF-8");
    }

    public String sign(PrivateKey privateKey, String data) {
        Signature sig = null;
        try {
            sig = Signature.getInstance("SHA256WithRSA", new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sig.initSign(privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            sig.update(data.getBytes("UTF8"));
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        byte[] signatureBytes = new byte[0];
        try {
            signatureBytes = sig.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        System.out.println(sig.getAlgorithm());
        //System.out.println("Signature : "+new BASE64Encoder().encode(signatureBytes.toString().getBytes()));
        return new BASE64Encoder().encode(signatureBytes);
    }

    public boolean verify(String pubKeyPath, String data,String signature) throws Exception{

        Signature signature1 = Signature.getInstance("SHA256WithRSA", new BouncyCastleProvider());
        signature1.initVerify(new RSA.KeyUtil().getPublicKey(pubKeyPath));
        signature1.update(data.getBytes());

        return signature1.verify(new BASE64Decoder().decodeBuffer(signature));
    }

}
