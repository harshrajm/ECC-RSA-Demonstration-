package RSA;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Encoder;
import sun.security.x509.*;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by Administrator on 15-09-2017.
 */
public class CerUtil {

    public void generateCER(String filepath, PublicKey publicKey, PrivateKey caPrivateKey, String email, String cn, String ou, String l, String o, String st, String c, String caCommonName) throws Exception {
        String distinguishedName = "EMAILADDRESS=" + email + ",CN=" + cn + ", OU=" + ou + ",L=" + l + ", O=" + o + ",ST=" + st + ", C=" + c;
        //CaCommonName = "CN=www.idrbtCA.com"
        X509Certificate certificate = generateCertificate(distinguishedName, publicKey, caPrivateKey, 365, "SHA256withRSA", caCommonName);
        String cerStr = "-----BEGIN CERTIFICATE-----\n" + new BASE64Encoder().encode(certificate.getEncoded()) + "\n-----END CERTIFICATE-----";
        KeyUtil.writeToFile(filepath, cerStr.getBytes());
    }

    public PublicKey getPublicKeyfromCER(String cerFilepath) throws Exception {
        PublicKey publicKey = null;
        FileInputStream fis = new FileInputStream(cerFilepath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            Certificate cert = cf.generateCertificate(bis);
            //System.out.println(cert.toString());
            publicKey = cert.getPublicKey();
            /*System.out.println(key);
            PublicKey publicKey = getCaPublic("FilesCA/publicKeyCA");
            System.out.println("PublicKey :" + publicKey);
            cert.verify(publicKey);*/

        }
        return publicKey;
    }

    public void verifyCER(String cerFilepath, PublicKey caPublicKey) throws Exception {
        PublicKey publicKey = null;
        FileInputStream fis = new FileInputStream(cerFilepath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            Certificate cert = cf.generateCertificate(bis);
            //System.out.println(cert.toString());
            // publicKey = cert.getPublicKey();
            //System.out.println(key);
            // PublicKey publicKey = getCaPublic("FilesCA/publicKeyCA");
            //System.out.println("PublicKey :" + publicKey);
            cert.verify(caPublicKey);
        }
    }

    public static X509Certificate generateCertificate(String dn, PublicKey publicKey, PrivateKey caPrivateKey, int days, String algorithm, String ccaCN)
            throws GeneralSecurityException, IOException {
        PrivateKey privkey = caPrivateKey;
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);
        X500Name ownerCA = new X500Name(ccaCN);
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, ownerCA);
        //here

        info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);

        // Update the algorith, and resign.
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);
        return cert;
    }

    public boolean isDateValid(String cerPath) throws Exception{
        FileInputStream fis = new FileInputStream(cerPath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        while (bis.available() > 0) {
            X509Certificate cert =(X509Certificate) cf.generateCertificate(bis);
            //System.out.println("Serial no : "+cert.getSerialNumber());
            //System.out.println("Not after : "+cert.getNotAfter());
            //System.out.println("Not before : "+cert.getNotBefore());
            Date before = cert.getNotBefore();
            Date after = cert.getNotAfter();
            Date today = new Date();
            if(today.after(before) && today.before(after)) {
                // In between
                System.out.println("Date of .cer valid!!");
                return true;
            }else {
                System.out.println("Date of .cer invalid!!");

            }
        }
        return false;
    }

    public String[] getDataFromCer(String cerPath) throws Exception{
        //0.email
        //1.cn
        //2.ou
        //3.l
        //4.o
        //5.st
        //6.c
        String[] dataArray = new String[7];
        FileInputStream fis = new FileInputStream(cerPath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());
        while (bis.available() > 0) {
            X509Certificate cert =(X509Certificate) cf.generateCertificate(bis);
            org.bouncycastle.asn1.x500.X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
            org.bouncycastle.asn1.x500.RDN email = x500name.getRDNs(BCStyle.EmailAddress)[0];
            dataArray[0] =  IETFUtils.valueToString(email.getFirst().getValue());
            org.bouncycastle.asn1.x500.RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            dataArray[1] =  IETFUtils.valueToString(cn.getFirst().getValue());
            org.bouncycastle.asn1.x500.RDN ou = x500name.getRDNs(BCStyle.OU)[0];
            dataArray[2] =  IETFUtils.valueToString(ou.getFirst().getValue());
            org.bouncycastle.asn1.x500.RDN l = x500name.getRDNs(BCStyle.L)[0];
            dataArray[3] =  IETFUtils.valueToString(l.getFirst().getValue());
            org.bouncycastle.asn1.x500.RDN o = x500name.getRDNs(BCStyle.O)[0];
            dataArray[4] =  IETFUtils.valueToString(o.getFirst().getValue());
            org.bouncycastle.asn1.x500.RDN st = x500name.getRDNs(BCStyle.ST)[0];
            dataArray[5] =  IETFUtils.valueToString(st.getFirst().getValue());
            org.bouncycastle.asn1.x500.RDN c = x500name.getRDNs(BCStyle.C)[0];
            dataArray[6] =  IETFUtils.valueToString(c.getFirst().getValue());
            return dataArray;
        }
        return null;
    }

    public static X509Certificate getCertificate(String filePath) throws Exception{
        FileInputStream fis = new FileInputStream(filePath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());

        X509Certificate cert =(X509Certificate) cf.generateCertificate(bis);
        return cert;
    }
}
