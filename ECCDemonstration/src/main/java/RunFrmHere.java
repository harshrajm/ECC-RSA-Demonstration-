import ECC.EncDecUtil;
import RSA.CerUtil;
import RSA.CsrUtil;
import RSA.KeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.pkcs12.PKCS12KeyStore;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class RunFrmHere {

    public static void main(String[] args) throws Exception {

        Scanner sc = new Scanner(System.in);

        System.out.println("Choose from below:");

        System.out.println("\n1. CCA initialise");
        System.out.println("2. CA initialise");
        System.out.println("3. Sub CA initialise");
        System.out.println("4. Subscriber 1 & 2 initialise");
        System.out.println("5. Sign and Verify");
        System.out.println("6. pfx test");
        int response = sc.nextInt();

        switch (response) {
            case 1:
                System.out.println("\n--> 1 Selected");
                new KeyUtil().generateKeys(PathUtils.CCA_PUB_KEY, PathUtils.CCA_PRI_KEY);
                System.out.println("-> CCA public and private keys generated");

                System.out.println("Enter Details to generate CCA CSR");
                System.out.println("Enter email:");
                String email = readString();
                System.out.println("Enter common name");
                String cn = readString();
                System.out.println("Enter Organization unit");
                String ou = readString();
                System.out.println("Enter Locality");
                String l = readString();
                System.out.println("Enter Organization");
                String o = readString();
                System.out.println("Enter State");
                String st = readString();
                System.out.println("Enter Country");
                String c = readString();

                new CsrUtil().generateCSR(PathUtils.CCA_CSR, new KeyUtil().getPublicKey(PathUtils.CCA_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.CCA_PRI_KEY), email, cn, ou, l, o, st, "IN");
                System.out.println("-> CCA CSR(certificate signing request) generated.");

                System.out.println("-> Generating CCA certificate...");
                String[] dataFrmCsr = new CsrUtil().getDataFromCSR(PathUtils.CCA_CSR);
                new CerUtil().generateCER(PathUtils.CCA_CER, new KeyUtil().getPublicKey(PathUtils.CCA_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.CCA_PRI_KEY), dataFrmCsr[0], dataFrmCsr[1], dataFrmCsr[2],
                        dataFrmCsr[3], dataFrmCsr[4], dataFrmCsr[5], dataFrmCsr[6], "CN=" + dataFrmCsr[1]);
                System.out.println("-> CCA Self signed certificate generated (RSA Root) in location :"+PathUtils.CCA_CER);
                System.out.println("\n--End of Action--\n");
                break;

            case 2:
                System.out.println("\n--> 2 Selected");
                new KeyUtil().generateKeys(PathUtils.CA_PUB_KEY, PathUtils.CA_PRI_KEY);
                System.out.println("-> CA public and private keys generated");

                System.out.println("Enter Details to generate CA CSR");
                System.out.println("Enter email:");
                String email1 = readString();
                System.out.println("Enter common name");
                String cn1 = readString();
                System.out.println("Enter Organization unit");
                String ou1 = readString();
                System.out.println("Enter Locality");
                String l1 = readString();
                System.out.println("Enter Organization");
                String o1 = readString();
                System.out.println("Enter State");
                String st1 = readString();
                System.out.println("Enter Country");
                String c1 = readString();

                new CsrUtil().generateCSR(PathUtils.CA_CSR, new KeyUtil().getPublicKey(PathUtils.CA_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.CA_PRI_KEY), email1, cn1, ou1, l1, o1, st1, "IN");
                System.out.println("-> CA CSR(certificate signing request) generated.");

                System.out.println("-> Generating CA certificate...");
                String[] dataFrmCsr1 = new CsrUtil().getDataFromCSR(PathUtils.CA_CSR);
                String[] dataFrmCsr2 = new CerUtil().getDataFromCer(PathUtils.CCA_CER);
                new CerUtil().generateCER(PathUtils.CA_CER, new KeyUtil().getPublicKey(PathUtils.CA_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.CCA_PRI_KEY), dataFrmCsr1[0], dataFrmCsr1[1], dataFrmCsr1[2],
                        dataFrmCsr1[3], dataFrmCsr1[4], dataFrmCsr1[5], dataFrmCsr1[6], "CN=" + dataFrmCsr2[1]);
                System.out.println("-> CA certificate generated which is signed by CCA at location :"+PathUtils.CA_CER);
                System.out.println("\n--End of Action--\n");
                break;

            case 3:
                System.out.println("\n--> 3 Selected");
                new ECC.KeyUtil().generateKeys(PathUtils.SUB_CA_PUB_KEY,PathUtils.SUB_CA_PRI_KEY);
                System.out.println("-> Sub CA public and private keys generated");
                System.out.println("Enter Details to generate Sub CA CSR");
                System.out.println("Enter email:");
                String email2 = readString();
                System.out.println("Enter common name");
                String cn2 = readString();
                System.out.println("Enter Organization unit");
                String ou2 = readString();
                System.out.println("Enter Locality");
                String l2 = readString();
                System.out.println("Enter Organization");
                String o2 = readString();
                System.out.println("Enter State");
                String st2 = readString();
                System.out.println("Enter Country");
                String c2 = readString();
                new ECC.CsrUtil().generateCSR(PathUtils.SUB_CA_CSR, new ECC.KeyUtil().getPublicKey(PathUtils.SUB_CA_PUB_KEY),
                        new ECC.KeyUtil().getPrivateKey(PathUtils.SUB_CA_PRI_KEY), email2, cn2, ou2,
                        l2, o2, st2, "IN");
                System.out.println("-> Sub CA CSR(certificate signing request) generated.");
                String[] dataCca = new CerUtil().getDataFromCer(PathUtils.CA_CER);
                String[] dataCa = new ECC.CsrUtil().getDataFromCSR(PathUtils.SUB_CA_CSR);
                new CerUtil().generateCER(PathUtils.SUB_CA_CER, new ECC.KeyUtil().getPublicKey(PathUtils.SUB_CA_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.CA_PRI_KEY), dataCa[0], dataCa[1], dataCa[2],
                        dataCa[3], dataCa[4], dataCa[5], "IN", "CN="+dataCca[1]);
                System.out.println("->SUB CA certificate generated which is signed by CA at location :"+PathUtils.SUB_CA_CER);
                System.out.println("\n--End of Action--\n");
                break;
            case 4:
                System.out.println("\n--> 4 Selected");
                initSub1AndSub2();
                break;

            case 5:
                System.out.println("\n--> 5 Selected");
                System.out.println("Enter data to sign:");
                String dataToSign = readString();

                System.out.println("\n->Choose private key to sign the data entered");
                System.out.println("1. Subscriber 1");
                System.out.println("2. Subscriber 2");
                String option = readString();
                String signature = null;
                if(option.equals("1")){
                    System.out.println("Signing data with Sub 1 Private Key");
                     signature = new EncDecUtil().sign(PathUtils.SUB_1_PRI_KEY, dataToSign);
                    System.out.println("Signature Generated:");
                    System.out.println("\n"+signature);
                }
                if(option.equals("2")){
                    System.out.println("Signing data with Sub 2 Private Key");
                    signature = new EncDecUtil().sign(PathUtils.SUB_2_PRI_KEY, dataToSign);
                    System.out.println("Signature Generated:");
                    System.out.println("\n"+signature);
                }

                System.out.println("\n-> Choose certificate to verify");
                System.out.println("1. Subscriber 1 Cer");
                System.out.println("2. Subscriber 2 Cer");
                String option1 = readString();
                if(option1.equals("1")){
                    boolean isVerified = new EncDecUtil().verify(PathUtils.SUB_1_PUB_KEY, dataToSign, signature);
                    System.out.println("\nIs Signature verified successfully : " + isVerified);
                }
                if(option1.equals("2")){
                    boolean isVerified = new EncDecUtil().verify(PathUtils.SUB_2_PUB_KEY, dataToSign, signature);
                    System.out.println("\nIs Signature verified successfully : " + isVerified);
                }


                break;
            case 6:
                testKeyStore();
                break;
        }

    }

    private static void initSub1AndSub2() throws Exception {

        new ECC.KeyUtil().createKeys(PathUtils.SUB_1_PUB_KEY, PathUtils.SUB_1_PRI_KEY);
        System.out.println("->Subscriber 1 public and private keys generated (ECC)");
        System.out.println("Enter Details to generate CSR for Subscriber 1...");
        System.out.println("Enter email:");
        String email2 = readString();
        System.out.println("Enter common name");
        String cn2 = readString();
        System.out.println("Enter Organization unit");
        String ou2 = readString();
        System.out.println("Enter Locality");
        String l2 = readString();
        System.out.println("Enter Organization");
        String o2 = readString();
        System.out.println("Enter State");
        String st2 = readString();
        System.out.println("Enter Country");
        String c2 = readString();

        new ECC.CsrUtil().generateCSR(PathUtils.SUB_1_CSR, new ECC.KeyUtil().getPublicKey(PathUtils.SUB_1_PUB_KEY),
                new ECC.KeyUtil().getPrivateKey(PathUtils.SUB_1_PRI_KEY), email2, cn2, ou2,
                l2, o2, st2, "IN");
        new ECC.CsrUtil().verifyCSR(PathUtils.SUB_1_CSR);
        String[] data = new ECC.CsrUtil().getDataFromCSR(PathUtils.SUB_1_CSR);
        String[] dataCa1 = new ECC.CerUtil().getDataFromCer(PathUtils.SUB_CA_CER);
        new ECC.CerUtil().generateCER(PathUtils.SUB_1_CER, new ECC.CsrUtil().getPublicKeyFromCSR(PathUtils.SUB_1_CSR),
                new ECC.KeyUtil().getPrivateKey(PathUtils.SUB_CA_PRI_KEY), data[0], data[1], data[2],
                data[3], data[4], data[5], data[6], dataCa1);
        System.out.println("->Subscriber 1 certificate generated which is signed by SUB CA at location :"+PathUtils.SUB_1_CER);

        new ECC.KeyUtil().createKeys(PathUtils.SUB_2_PUB_KEY, PathUtils.SUB_2_PRI_KEY);
        System.out.println("->Subscriber 2 public and private keys generated (ECC)");
        System.out.println("Enter Details to generate CSR for Subscriber 2...");
        System.out.println("Enter email:");
        String email3 = readString();
        System.out.println("Enter common name");
        String cn3 = readString();
        System.out.println("Enter Organization unit");
        String ou3 = readString();
        System.out.println("Enter Locality");
        String l3 = readString();
        System.out.println("Enter Organization");
        String o3 = readString();
        System.out.println("Enter State");
        String st3 = readString();
        System.out.println("Enter Country");
        String c3 = readString();
        new ECC.CsrUtil().generateCSR(PathUtils.SUB_2_CSR, new ECC.KeyUtil().getPublicKey(PathUtils.SUB_2_PUB_KEY),
                new ECC.KeyUtil().getPrivateKey(PathUtils.SUB_2_PRI_KEY), email3, cn3, ou3,
                l3, o3, st3, "IN");
        new ECC.CsrUtil().verifyCSR(PathUtils.SUB_2_CSR);
        String[] data1 = new ECC.CsrUtil().getDataFromCSR(PathUtils.SUB_2_CSR);
        new ECC.CerUtil().generateCER(PathUtils.SUB_2_CER, new ECC.CsrUtil().getPublicKeyFromCSR(PathUtils.SUB_2_CSR),
                new ECC.KeyUtil().getPrivateKey(PathUtils.SUB_CA_PRI_KEY), data1[0], data1[1], data1[2],
                data1[3], data1[4], data1[5], data1[6], dataCa1);
        System.out.println("->Subscriber 2 certificate generated which is signed by SUB CA at location :"+PathUtils.SUB_2_CER);

        System.out.println("\n--End of Action--\n");


    }

    private static String readString() {
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }



    public static void testKeyStore() throws Exception {
        try {
            String storeName = "files/pfx.pfx";


            X509Certificate selfCert = new CerUtil().getCertificate(PathUtils.CA_CER);
            PrivateKey privateKey = new KeyUtil().getPrivateKey(PathUtils.CA_PRI_KEY);

            java.security.cert.Certificate[] outChain = { selfCert };
            KeyStore outStore = KeyStore.getInstance("PKCS12");
            outStore.load(null, "password".toCharArray());
            outStore.setKeyEntry("mykey", privateKey, "password".toCharArray(),
                    outChain);
            OutputStream outputStream = new FileOutputStream(storeName);
            outStore.store(outputStream, "password".toCharArray());
            outputStream.flush();
            outputStream.close();

            KeyStore inStore = KeyStore.getInstance("PKCS12");
            inStore.load(new FileInputStream(storeName), "password".toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
            throw new AssertionError(e.getMessage());
        }
    }
}
