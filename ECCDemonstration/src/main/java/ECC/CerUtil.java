package ECC;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.misc.BASE64Encoder;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by Administrator on 15-09-2017.
 */
public class CerUtil {

    public void generateCER(String filepath, PublicKey publicKey,
                            PrivateKey caPrivateKey, String email, String cn, String ou, String l, String o, String st, String c, String[] caData) throws Exception {

        Security.addProvider(new BouncyCastleProvider());



        // Generate self-signed certificate
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, cn);
        builder.addRDN(BCStyle.EmailAddress,email);
        builder.addRDN(BCStyle.OU,ou);
        builder.addRDN(BCStyle.L,l);
        builder.addRDN(BCStyle.O,o);
        builder.addRDN(BCStyle.ST,st);
        builder.addRDN(BCStyle.C,c);

        X500NameBuilder builderCa = new X500NameBuilder(BCStyle.INSTANCE);
        builderCa.addRDN(BCStyle.EmailAddress,caData[0]);
        builderCa.addRDN(BCStyle.CN, caData[1]);
        builderCa.addRDN(BCStyle.OU,caData[2]);
        builderCa.addRDN(BCStyle.L,caData[3]);
        builderCa.addRDN(BCStyle.O,caData[4]);
        builderCa.addRDN(BCStyle.ST,caData[5]);
        builderCa.addRDN(BCStyle.C,caData[6]);
        Date from = new Date();
        Date to = new Date(from.getTime() + 365 * 86400000l);
        //Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        //Date notAfter = new Date(System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builderCa.build(),
                serial, from, to, builder.build(), publicKey);
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(new BouncyCastleProvider()).build(caPrivateKey);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(certGen.build(sigGen));

        //cert.checkValidity(new Date());
        //System.out.println(cert);

        //cert.verify(new KeyUtil().getPublicKey("files/test/testCAPubK"));
        String cerStr = "-----BEGIN CERTIFICATE-----\n" + new BASE64Encoder().encode(cert.getEncoded()) + "\n-----END CERTIFICATE-----";
        KeyUtil.writeToFile(filepath,cerStr.getBytes());
    }


    public PublicKey getPublicKey(String filePath) throws Exception{

        PublicKey publicKey = null;
        FileInputStream fis = new FileInputStream(filePath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());

        while (bis.available() > 0) {
            Certificate cert = cf.generateCertificate(bis);
            publicKey = cert.getPublicKey();
        }
        return publicKey;

    }

    public void verifyCER(String cerFilepath, PublicKey caPublicKey) throws Exception {
        PublicKey publicKey = null;
        FileInputStream fis = new FileInputStream(cerFilepath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());

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

    public boolean isDateValid(String cerPath) throws Exception{
        FileInputStream fis = new FileInputStream(cerPath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());
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


    public static X509Certificate getCertificate(String filePath) throws Exception{
        FileInputStream fis = new FileInputStream(filePath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());

        X509Certificate cert =(X509Certificate) cf.generateCertificate(bis);
        return cert;
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
            RDN email = x500name.getRDNs(BCStyle.EmailAddress)[0];
            dataArray[0] =  IETFUtils.valueToString(email.getFirst().getValue());
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            dataArray[1] =  IETFUtils.valueToString(cn.getFirst().getValue());
            RDN ou = x500name.getRDNs(BCStyle.OU)[0];
            dataArray[2] =  IETFUtils.valueToString(ou.getFirst().getValue());
            RDN l = x500name.getRDNs(BCStyle.L)[0];
            dataArray[3] =  IETFUtils.valueToString(l.getFirst().getValue());
            RDN o = x500name.getRDNs(BCStyle.O)[0];
            dataArray[4] =  IETFUtils.valueToString(o.getFirst().getValue());
            RDN st = x500name.getRDNs(BCStyle.ST)[0];
            dataArray[5] =  IETFUtils.valueToString(st.getFirst().getValue());
            RDN c = x500name.getRDNs(BCStyle.C)[0];
            dataArray[6] =  IETFUtils.valueToString(c.getFirst().getValue());
        return dataArray;
        }
    return null;
    }
}
