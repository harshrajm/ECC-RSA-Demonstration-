package ECC;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.misc.BASE64Encoder;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

public class CrlUtil {

    public void createBlankCrl(String filePath, PublicKey caPubKey, PrivateKey caPivateKey,String caCerPath) throws Exception {
        //Date now = new Date();


        Calendar cal = Calendar.getInstance();
        String[] caData = new CerUtil().getDataFromCer(caCerPath);

        X500NameBuilder builderCa = new X500NameBuilder(BCStyle.INSTANCE);
        builderCa.addRDN(BCStyle.CN, caData[1]);
        builderCa.addRDN(BCStyle.EmailAddress,caData[0]);
        builderCa.addRDN(BCStyle.OU,caData[2]);
        builderCa.addRDN(BCStyle.L,caData[3]);
        builderCa.addRDN(BCStyle.O,caData[4]);
        builderCa.addRDN(BCStyle.ST,caData[5]);
        builderCa.addRDN(BCStyle.C,caData[6]);

        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(builderCa.build(), cal.getTime());
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        cal.add(Calendar.YEAR, 1); // to get previous year add -1
        Date nextYear = cal.getTime();
        crlGen.setNextUpdate(nextYear);

        //crlGen.addCRLEntry(BigInteger.ONE, now, org.bouncycastle.asn1.x509.CRLReason.privilegeWithdrawn);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caPubKey));
        X509CRL x509CRL =  new JcaX509CRLConverter().setProvider(new BouncyCastleProvider()).getCRL(crlGen.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(new BouncyCastleProvider()).build(caPivateKey)));
        String crlInFormat = "-----BEGIN X509 CRL-----\n"+ new BASE64Encoder().encode(x509CRL.getEncoded())+"\n-----END X509 CRL-----";
        KeyUtil.writeToFile(filePath,crlInFormat.getBytes());
    }


    public void addCertToCrl(X509Certificate certificate,String crlPath,PublicKey caPubKey, PrivateKey caPivateKey,String caCerPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());
        FileInputStream in = new FileInputStream(crlPath);
        X509CRL crl = (X509CRL) cf.generateCRL(in);

        Set s = crl.getRevokedCertificates();

        //create crl steps
        Calendar cal = Calendar.getInstance();
        String[] caData = new CerUtil().getDataFromCer(caCerPath);

        X500NameBuilder builderCa = new X500NameBuilder(BCStyle.INSTANCE);
        builderCa.addRDN(BCStyle.CN, caData[1]);
        builderCa.addRDN(BCStyle.EmailAddress,caData[0]);
        builderCa.addRDN(BCStyle.OU,caData[2]);
        builderCa.addRDN(BCStyle.L,caData[3]);
        builderCa.addRDN(BCStyle.O,caData[4]);
        builderCa.addRDN(BCStyle.ST,caData[5]);
        builderCa.addRDN(BCStyle.C,caData[6]);

        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(builderCa.build(), cal.getTime());
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        cal.add(Calendar.YEAR, 1); // to get previous year add -1
        Date nextYear = cal.getTime();
        crlGen.setNextUpdate(nextYear);

        if (s != null && s.isEmpty() == false) {
            Iterator t = s.iterator();
            while (t.hasNext()) {
                X509CRLEntry entry = (X509CRLEntry) t.next();
                System.out.println("serial number = " + entry.getSerialNumber().toString(16));
                System.out.println("revocation date = " + entry.getRevocationDate());
                System.out.println("extensions = " + entry.hasExtensions());

                crlGen.addCRLEntry(entry.getSerialNumber(),entry.getRevocationDate(),9);
            }


        }
        crlGen.addCRLEntry(certificate.getSerialNumber(),new Date(),9);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caPubKey));
        X509CRL x509CRL =  new JcaX509CRLConverter().setProvider(new BouncyCastleProvider()).getCRL(crlGen.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(new BouncyCastleProvider()).build(caPivateKey)));

        String crlInFormat = "-----BEGIN X509 CRL-----\n"+ new BASE64Encoder().encode(x509CRL.getEncoded())+"\n-----END X509 CRL-----";

        KeyUtil.writeToFile(crlPath,crlInFormat.getBytes());
    }

    public boolean checkIfRevoked(String crlPath, String cerPath) throws Exception{
        FileInputStream fis = new FileInputStream(cerPath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());

        X509Certificate cert =(X509Certificate) cf.generateCertificate(bis);

        CertificateFactory cf1 = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());
        FileInputStream in = new FileInputStream(crlPath);
        X509CRL crl = (X509CRL) cf1.generateCRL(in);
        //System.out.println(crl.getRevokedCertificates());
        Set s = crl.getRevokedCertificates();
        if (s != null && s.isEmpty() == false) {
            Iterator t = s.iterator();
            while (t.hasNext()) {
                X509CRLEntry entry = (X509CRLEntry) t.next();
                //System.out.println("serial number = " + entry.getSerialNumber().toString(16));
                //System.out.println("revocation date = " + entry.getRevocationDate());
                //System.out.println("extensions = " + entry.hasExtensions());
                System.out.println("comparing "+entry.getSerialNumber()+" to "+cert.getSerialNumber());
                if(entry.getSerialNumber().equals(cert.getSerialNumber())){
                    return true;

                }
            }


        }

        return false;

    }



    public void isCrlSignedByCA(String crlPath,PublicKey caPK) throws Exception{
        CertificateFactory cf1 = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());
        FileInputStream in = new FileInputStream(crlPath);
        X509CRL crl = (X509CRL) cf1.generateCRL(in);
        crl.verify(caPK);
        /*System.out.println(crl.getSignature());
        byte[] signatureBytes = crl.getSignature();

        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initVerify(caPK);
        sig.update(crl.getEncoded());
        sig.verify(signatureBytes);
        System.out.println(sig.verify(signatureBytes));*/

    }


}
