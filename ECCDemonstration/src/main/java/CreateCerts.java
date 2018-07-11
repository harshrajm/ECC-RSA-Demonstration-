import RSA.CerUtil;
import RSA.KeyUtil;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CreateCerts {
    //CCA
    private static final String CCA_EMAIL = "cca@email.com";
    private static final String CCA_CN = "www.testcca.com";
    private static final String CCA_OU = "CCA";
    private static final String CCA_L = "Hitech City";
    private static final String CCA_O = "TEST CCA Org";
    private static final String CCA_ST = "Telangana";
    private static final String CCA_C = "IN";
    private static final String CCA_IN_STR = "EMAILADDRESS="+CCA_EMAIL+",CN="+CCA_CN+",OU="+CCA_OU+",L="+CCA_L+",O="+CCA_O +
            ",ST="+CCA_ST+",C="+CCA_C;
    //CA
    private static final String CA_EMAIL = "ca@email.com";
    private static final String CA_CN = "www.testca.com";
    private static final String CA_OU = "CA";
    private static final String CA_L = "Masab Tank";
    private static final String CA_O = "IDRBT TEST CA";
    private static final String CA_ST = "Telangana";
    private static final String CA_C = "IN";
    private static final String[]CA_ARR = new String[]{CA_EMAIL,CA_CN,CA_OU,CA_L,CA_O,CA_ST,CA_C};
    private static final String CA_IN_STR = "EMAILADDRESS="+CA_EMAIL+",CN="+CA_CN+",OU="+CA_OU+",L="+CA_L+",O="+CA_O +
            ",ST="+CA_ST+",C="+CA_C;

    //SUBCA
    private static final String SUB_CA_EMAIL = "subca@email.com";
    private static final String SUB_CA_CN = "www.testSubca.com";
    private static final String SUB_CA_OU = "SUB CA";
    private static final String SUB_CA_L = "Masab Tank";
    private static final String SUB_CA_O = "IDRBT TEST SUB CA";
    private static final String SUB_CA_ST = "Telangana";
    private static final String SUB_CA_C = "IN";
    private static final String[]SUB_CA_ARR = new String[]{SUB_CA_EMAIL,SUB_CA_CN,SUB_CA_OU,SUB_CA_L,SUB_CA_O,SUB_CA_ST,SUB_CA_C};
    private static final String SUB_CA_IN_STR = "EMAILADDRESS="+SUB_CA_EMAIL+",CN="+SUB_CA_CN+",OU="+SUB_CA_OU+",L="+
            SUB_CA_L+",O="+SUB_CA_O +",ST="+SUB_CA_ST+",C="+SUB_CA_C;

    //SRI
    private static final String SRI_EMAIL = "tsrikanth@idrbt.ac.in";
    private static final String SRI_CN = "www.idrbt.ac.in";
    private static final String SRI_OU = "Center For Mobile Banking";
    private static final String SRI_L = "Masab Tank";
    private static final String SRI_O = "IDRBT";
    private static final String SRI_ST = "Telangana";
    private static final String SRI_C = "IN";
    //PAV
    private static final String PAV_EMAIL = "vlnpavani@idrbt.ac.in";
    //RAM
    private static final String RAM_EMAIL = "kvramya@idrbt.ac.in";
    //DAV
    private static final String DAV_EMAIL = "npdhavale@idrbt.ac.in";
    private static final String DAV_CN = "npdhavale";


    public static void main(String[] args) throws Exception{

        //CCA initialize
        new KeyUtil().generateKeys(PathUtils.CERTS_CCA_PUB_KEY,PathUtils.CERTS_CCA_PRI_KEY);
        new CerUtil().generateCER(PathUtils.CERTS_CCA_CER,new KeyUtil().getPublicKey(PathUtils.CERTS_CCA_PUB_KEY),
                new KeyUtil().getPrivateKey(PathUtils.CERTS_CCA_PRI_KEY),CCA_EMAIL,CCA_CN,CCA_OU,CCA_L,CCA_O,CCA_ST,CCA_C,
                CCA_IN_STR);

        //CA initialize
        new KeyUtil().generateKeys(PathUtils.CERTS_CA_PUB_KEY,PathUtils.CERTS_CA_PRI_KEY);
        new CerUtil().generateCER(PathUtils.CERTS_CA_CER,new KeyUtil().getPublicKey(PathUtils.CERTS_CA_PUB_KEY),
                new KeyUtil().getPrivateKey(PathUtils.CERTS_CCA_PRI_KEY),CA_EMAIL,CA_CN,CA_OU,CA_L,CA_O,CA_ST,CA_C,CCA_IN_STR);

        //Sub CA initialize
        /*new ECC.KeyUtil().generateKeys(PathUtils.CERTS_SUB_CA_PUB_KEY,PathUtils.CERTS_SUB_CA_PRI_KEY);
        new CerUtil().generateCER(PathUtils.CERTS_SUB_CA_CER,new ECC.KeyUtil().getPublicKey(PathUtils.CERTS_SUB_CA_PUB_KEY),
                new KeyUtil().getPrivateKey(PathUtils.CERTS_CA_PRI_KEY),SUB_CA_EMAIL,SUB_CA_CN,SUB_CA_OU,SUB_CA_L,SUB_CA_O,
                SUB_CA_ST,SUB_CA_C,CA_IN_STR);*/

        // RSA Subscribers
        new KeyUtil().generateKeys(PathUtils.CERTS_SRI_RSA_PUB_KEY,PathUtils.CERTS_SRI_RSA_PRI_KEY);
        new KeyUtil().generateKeys(PathUtils.CERTS_PAV_RSA_PUB_KEY,PathUtils.CERTS_PAV_RSA_PRI_KEY);
        new KeyUtil().generateKeys(PathUtils.CERTS_RAM_RSA_PUB_KEY,PathUtils.CERTS_RAM_RSA_PRI_KEY);
        new KeyUtil().generateKeys(PathUtils.CERTS_DAV_RSA_PUB_KEY,PathUtils.CERTS_DAV_RSA_PRI_KEY);

        new CerUtil().generateCER(PathUtils.CERTS_SRI_RSA_CER,new KeyUtil().getPublicKey(PathUtils.CERTS_SRI_RSA_PUB_KEY),
                new KeyUtil().getPrivateKey(PathUtils.CERTS_CA_PRI_KEY),SRI_EMAIL,SRI_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,CA_IN_STR);
        new CerUtil().generateCER(PathUtils.CERTS_PAV_RSA_CER,new KeyUtil().getPublicKey(PathUtils.CERTS_PAV_RSA_PUB_KEY),
                new KeyUtil().getPrivateKey(PathUtils.CERTS_CA_PRI_KEY),PAV_EMAIL,SRI_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,CA_IN_STR);
        new CerUtil().generateCER(PathUtils.CERTS_RAM_RSA_CER,new KeyUtil().getPublicKey(PathUtils.CERTS_RAM_RSA_PUB_KEY),
                new KeyUtil().getPrivateKey(PathUtils.CERTS_CA_PRI_KEY),RAM_EMAIL,SRI_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,CA_IN_STR);
        new CerUtil().generateCER(PathUtils.CERTS_DAV_RSA_CER,new KeyUtil().getPublicKey(PathUtils.CERTS_DAV_RSA_PUB_KEY),
                new KeyUtil().getPrivateKey(PathUtils.CERTS_CA_PRI_KEY),DAV_EMAIL,DAV_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,CA_IN_STR);
        //RSA PFX
        testKeyStore(PathUtils.PFX_SRI,PathUtils.CERTS_SRI_RSA_CER,PathUtils.CERTS_SRI_RSA_PRI_KEY);
        testKeyStore(PathUtils.PFX_PAV,PathUtils.CERTS_PAV_RSA_CER,PathUtils.CERTS_PAV_RSA_PRI_KEY);
        testKeyStore(PathUtils.PFX_DAV,PathUtils.CERTS_DAV_RSA_CER,PathUtils.CERTS_DAV_RSA_PRI_KEY);
        testKeyStore(PathUtils.PFX_RAM,PathUtils.CERTS_RAM_RSA_CER,PathUtils.CERTS_RAM_RSA_PRI_KEY);
        /*new ECC.KeyUtil().generateKeys(PathUtils.CERTS_SRI_ECC_PUB_KEY,PathUtils.CERTS_SRI_ECC_PRI_KEY);
        new ECC.KeyUtil().generateKeys(PathUtils.CERTS_PAV_ECC_PUB_KEY,PathUtils.CERTS_PAV_ECC_PRI_KEY);
        new ECC.KeyUtil().generateKeys(PathUtils.CERTS_DAV_ECC_PUB_KEY,PathUtils.CERTS_DAV_ECC_PRI_KEY);
        new ECC.KeyUtil().generateKeys(PathUtils.CERTS_RAM_ECC_PUB_KEY,PathUtils.CERTS_RAM_ECC_PRI_KEY);

        new ECC.CerUtil().generateCER(PathUtils.CERTS_SRI_ECC_CER,new ECC.KeyUtil().getPublicKey(PathUtils.CERTS_SRI_ECC_PUB_KEY),
                new ECC.KeyUtil().getPrivateKey(PathUtils.CERTS_SUB_CA_PRI_KEY),SRI_EMAIL,SRI_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,SUB_CA_ARR);
        new ECC.CerUtil().generateCER(PathUtils.CERTS_PAV_ECC_CER,new ECC.KeyUtil().getPublicKey(PathUtils.CERTS_PAV_ECC_PUB_KEY),
                new ECC.KeyUtil().getPrivateKey(PathUtils.CERTS_SUB_CA_PRI_KEY),PAV_EMAIL,SRI_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,SUB_CA_ARR);
        new ECC.CerUtil().generateCER(PathUtils.CERTS_DAV_ECC_CER,new ECC.KeyUtil().getPublicKey(PathUtils.CERTS_DAV_ECC_PUB_KEY),
                new ECC.KeyUtil().getPrivateKey(PathUtils.CERTS_SUB_CA_PRI_KEY),DAV_EMAIL,SRI_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,SUB_CA_ARR);
        new ECC.CerUtil().generateCER(PathUtils.CERTS_RAM_ECC_CER,new ECC.KeyUtil().getPublicKey(PathUtils.CERTS_RAM_ECC_PUB_KEY),
                new ECC.KeyUtil().getPrivateKey(PathUtils.CERTS_SUB_CA_PRI_KEY),RAM_EMAIL,SRI_CN,SRI_OU,SRI_L,SRI_O,
                SRI_ST,SRI_C,SUB_CA_ARR);
*/
    }

    public static void testKeyStore(String storeName,String cerPath, String priKPath) throws Exception {
        try {
            //String storeName = "certs/sri.pfx";


            X509Certificate selfCert = new CerUtil().getCertificate(cerPath);
            PrivateKey privateKey = new KeyUtil().getPrivateKey(priKPath);

            java.security.cert.Certificate[] outChain = { selfCert };
            KeyStore outStore = KeyStore.getInstance("PKCS12");
            outStore.load(null, "idrbt@123".toCharArray());
            outStore.setKeyEntry("mykey", privateKey, "idrbt@123".toCharArray(),
                    outChain);
            OutputStream outputStream = new FileOutputStream(storeName);
            outStore.store(outputStream, "idrbt@123".toCharArray());
            outputStream.flush();
            outputStream.close();

            KeyStore inStore = KeyStore.getInstance("PKCS12");
            inStore.load(new FileInputStream(storeName), "idrbt@123".toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
            throw new AssertionError(e.getMessage());
        }
    }
}
