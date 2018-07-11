package RSA;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCSException;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Created by Administrator on 15-09-2017.
 */
public class CsrUtil {
    private static final String COUNTRY = "2.5.4.6";
    private static final String STATE = "2.5.4.8";
    private static final String LOCALE = "2.5.4.7";
    private static final String ORGANIZATION = "2.5.4.10";
    private static final String ORGANIZATION_UNIT = "2.5.4.11";
    private static final String COMMON_NAME = "2.5.4.3";
    private static final String EMAIL = "2.5.4.9";

    public boolean verifyCSR(String csrFilePath) throws NoSuchAlgorithmException,
            SignatureException, InvalidKeyException, InvalidKeySpecException, IOException {
        PublicKey  publicKey = null;
                String[] dataArray = new String[7];
        byte[] keyBytes =null;
        RSAKeyParameters pubkey = null;

        try {
            keyBytes = Files.readAllBytes(new File(csrFilePath).toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        InputStream stream = new ByteArrayInputStream(keyBytes);
        org.bouncycastle.pkcs.PKCS10CertificationRequest  csr = convertPemToPKCS10CertificationRequest(stream);

        pubkey = (RSAKeyParameters) PublicKeyFactory.createKey(csr.getSubjectPublicKeyInfo());

        byte[] encodedByte = csr.getSignature();
        Signature sig = Signature.getInstance("SHA256WithRSA");
        //sig.update(encodedByte);

        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(pubkey.getModulus(), pubkey.getExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        publicKey = kf.generatePublic(rsaSpec);

        sig.initVerify(publicKey);
        boolean result = false;
        try {
            result =  csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey));
        } catch (PKCSException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
        System.out.println("verification : "+result);
    return result;
    }


    public void generateCSR(String filePath, PublicKey publicKey, PrivateKey privateKey,
                            String email,String cn, String ou, String l,String o,String st,String c) throws Exception{

        PKCS10 pkcs10 = new PKCS10(publicKey);
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey);
        X500Principal principal = new X500Principal("EMAILADDRESS="+email+",CN="+cn+", OU="+ou+",L="+l+", O="+o+",ST="+st+", C="+c);
        X500Name x500name = null;
        x500name = new X500Name(principal.getEncoded());
        pkcs10.encodeAndSign(x500name, signature);
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        byte[] byteArray = bs.toByteArray();
        String csr = new String(byteArray);

        KeyUtil.writeToFile(filePath, csr.getBytes());

    }

    public String[] getDataFromCSR(String filePath){
        String[] dataArray = new String[7];
        byte[] keyBytes =null;

        try {
            keyBytes = Files.readAllBytes(new File(filePath).toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        InputStream stream = new ByteArrayInputStream(keyBytes);
        org.bouncycastle.pkcs.PKCS10CertificationRequest  csr = convertPemToPKCS10CertificationRequest(stream);
        org.bouncycastle.asn1.x500.X500Name x500Name = csr.getSubject();
        dataArray[6] = getX500Field(COUNTRY, x500Name);
        dataArray[5] = getX500Field(STATE, x500Name);
        dataArray[3] = getX500Field(LOCALE, x500Name);
        dataArray[4] = getX500Field(ORGANIZATION, x500Name);
        dataArray[2] = getX500Field(ORGANIZATION_UNIT, x500Name);
        dataArray[1] = getX500Field(COMMON_NAME, x500Name);
        RDN cn = x500Name.getRDNs(BCStyle.EmailAddress)[0];
        dataArray[0] = cn.getFirst().getValue().toString();

        return dataArray;
    }

    public PublicKey getPublicKeyFromCSR(String filePath) throws Exception{
        String[] dataArray = new String[7];
        byte[] keyBytes =null;
        RSAKeyParameters pubkey = null;

        try {
            keyBytes = Files.readAllBytes(new File(filePath).toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        InputStream stream = new ByteArrayInputStream(keyBytes);
        org.bouncycastle.pkcs.PKCS10CertificationRequest  csr = convertPemToPKCS10CertificationRequest(stream);

        try {
            pubkey =
                    (RSAKeyParameters) PublicKeyFactory.createKey(csr.getSubjectPublicKeyInfo());
            System.out.println("public key : "+pubkey.getModulus());
        } catch (IOException e) {
            e.printStackTrace();
        }
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(pubkey.getModulus(), pubkey.getExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey rsaPub = kf.generatePublic(rsaSpec);

        return rsaPub;
    }

    //-------------------------------------------------------------------------------------------------------------------------

    private static String getX500Field(String asn1ObjectIdentifier, org.bouncycastle.asn1.x500.X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));

        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }
        return retVal;
    }
    private static org.bouncycastle.pkcs.PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(InputStream pem) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;

        pemStream = (ByteArrayInputStream) pem;

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = null;
        try {
            pemParser = new PEMParser(pemReader);
            Object parsedObj = pemParser.readObject();
           // System.out.println("PemParser returned: " + parsedObj);
            if (parsedObj instanceof org.bouncycastle.pkcs.PKCS10CertificationRequest) {
                csr = (org.bouncycastle.pkcs.PKCS10CertificationRequest) parsedObj;
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (pemParser != null) {
            }
        }
        return csr;
    }



}
