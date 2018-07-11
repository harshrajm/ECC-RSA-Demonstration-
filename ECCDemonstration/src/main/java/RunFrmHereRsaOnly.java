import ECC.EncDecUtil;
import RSA.*;

import java.security.cert.X509Certificate;
import java.util.Scanner;

public class RunFrmHereRsaOnly {


    public static void main(String[] args) throws Exception {

        Scanner sc = new Scanner(System.in);

        System.out.println("Choose from below:");

        System.out.println("1. CCA initialise");
        System.out.println("2. CA initialise");
        System.out.println("3. Subscriber 1 & 2 initialise");
        System.out.println("4. Sub 1 Sign Data and Sub 2 verifies it");
        //System.out.println("5. Sub 2 Verifies data signed by Sub 1");
        System.out.println("5. create blank CRL");
        System.out.println("6. add certificate to CRL");

        int response = sc.nextInt();

        switch (response) {
            case 1:
                new KeyUtil().generateKeys(PathUtils.R_CCA_NODE_PUB_KEY, PathUtils.R_CCA_NODE_PRI_KEY);
                System.out.println("-> CCA public and private keys generated");

                System.out.println("Enter Details to generate CSR");
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

                new CsrUtil().generateCSR(PathUtils.R_CCA_NODE_CSR, new KeyUtil().getPublicKey(PathUtils.R_CCA_NODE_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_CCA_NODE_PRI_KEY), email, cn, ou, l, o, st, "IN");
                System.out.println("-> CCA CSR(certificate signing request) generated");


                String[] dataFrmCsr = new CsrUtil().getDataFromCSR(PathUtils.R_CCA_NODE_CSR);
                new CerUtil().generateCER(PathUtils.R_CCA_NODE_CER, new KeyUtil().getPublicKey(PathUtils.R_CCA_NODE_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_CCA_NODE_PRI_KEY), dataFrmCsr[0], dataFrmCsr[1], dataFrmCsr[2],
                        dataFrmCsr[3], dataFrmCsr[4], dataFrmCsr[5], dataFrmCsr[6], "CN="+dataFrmCsr[1]);
                System.out.println("-> CCA Self signed certificate generated (RSA Root)");
                break;

            case 2:
                new KeyUtil().generateKeys(PathUtils.R_CA_NODE_PUB_KEY, PathUtils.R_CA_NODE_PRI_KEY);
                System.out.println("-> CA public and private key generated");

                System.out.println("Enter Details to generate CSR");
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

                new CsrUtil().generateCSR(PathUtils.R_CA_NODE_CSR, new KeyUtil().getPublicKey(PathUtils.R_CA_NODE_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_CA_NODE_PRI_KEY), email1, cn1, ou1,
                        l1, o1, st1, "IN");
                System.out.println("-> CA CSR(certificate signing request) generated");
                new CsrUtil().verifyCSR(PathUtils.R_CA_NODE_CSR);
                System.out.println("-> CA CSR verified!!");
                String[] dataCca = new CerUtil().getDataFromCer(PathUtils.R_CCA_NODE_CER);
                String[] dataCa = new CsrUtil().getDataFromCSR(PathUtils.R_CA_NODE_CSR);
                new CerUtil().generateCER(PathUtils.R_CA_NODE_CER, new KeyUtil().getPublicKey(PathUtils.R_CA_NODE_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_CA_NODE_PRI_KEY), dataCa[0], dataCa[1], dataCa[2],
                        dataCa[3], dataCa[4], dataCa[5], "IN", "CN="+dataCca[1]);

                //CER signed by RSA
                /*new CerUtil().generateCER(PathUtils.ECC_NODE_CER,new ECC.KeyUtil().getPublicKey(PathUtils.ECC_NODE_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.RSA_NODE_PRI_KEY),"ecc@email.com","www.ecc.com","ecc cert team",
                        "indira nagar","ecc","Karnataka","IN","CN=www.rsa.com");*/
                System.out.println("-> CA Certificate generated which is signed by CCA");
                break;


            case 3:
                new KeyUtil().generateKeys(PathUtils.R_NODE_1_PUB_KEY, PathUtils.R_NODE_1_PRI_KEY);

                System.out.println("Enter Details to generate CSR");
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

                new CsrUtil().generateCSR(PathUtils.R_NODE_1_CSR, new KeyUtil().getPublicKey(PathUtils.R_NODE_1_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_NODE_1_PRI_KEY), email2, cn2, ou2,
                        l2, o2, st2, "IN");
                new CsrUtil().verifyCSR(PathUtils.R_NODE_1_CSR);
                String[] data = new CsrUtil().getDataFromCSR(PathUtils.R_NODE_1_CSR);
                String[] dataCa1 = new CerUtil().getDataFromCer(PathUtils.R_CA_NODE_CER);
                new CerUtil().generateCER(PathUtils.R_NODE_1_CER, new CsrUtil().getPublicKeyFromCSR(PathUtils.R_NODE_1_CSR),
                        new KeyUtil().getPrivateKey(PathUtils.R_CA_NODE_PRI_KEY), data[0], data[1], data[2],
                        data[3], data[4], data[5], data[6], "CN="+dataCa1[1]);

                new KeyUtil().generateKeys(PathUtils.R_NODE_2_PUB_KEY, PathUtils.R_NODE_2_PRI_KEY);

                System.out.println("Enter Details to generate CSR");
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
                new CsrUtil().generateCSR(PathUtils.R_NODE_2_CSR, new KeyUtil().getPublicKey(PathUtils.R_NODE_2_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_NODE_2_PRI_KEY), email3, cn3, ou3,
                        l3, o3, st3, "IN");
                new CsrUtil().verifyCSR(PathUtils.R_NODE_2_CSR);
                String[] data1 = new CsrUtil().getDataFromCSR(PathUtils.R_NODE_2_CSR);
                //String[] dataCa1 = new ECC.CerUtil().getDataFromCer(PathUtils.ECC_NODE_CER);
                new CerUtil().generateCER(PathUtils.R_NODE_2_CER, new CsrUtil().getPublicKeyFromCSR(PathUtils.R_NODE_2_CSR),
                        new KeyUtil().getPrivateKey(PathUtils.R_CA_NODE_PRI_KEY), data1[0], data1[1], data1[2],
                        data1[3], data1[4], data1[5], data1[6], "CN="+dataCa1[1]);

                System.out.println("done!");
                break;

            case 4:

                System.out.println("Enter data to sign:");
                String dataToSign = readString();
                String signature = new EncDcrpt().sign(new KeyUtil().getPrivateKey(PathUtils.R_NODE_1_PRI_KEY), dataToSign);
                System.out.println("Signature :");
                System.out.println(signature);
                System.out.println("");
                System.out.println("Starting verification...");
                System.out.println("data : "+dataToSign);
                System.out.println("Signature : "+signature);
                System.out.println("press 1 for verification....");
                String no = readString();
                if(no.equals("1")){
                    boolean isVerified = new EncDcrpt().verify(PathUtils.R_NODE_1_PUB_KEY, dataToSign, signature);
                    System.out.println("is Signature verified successfully : " + isVerified);
                }
                break;

            case 5:
                String crlPath = "files/RSA/crl.crl";
                new CrlUtil().createBlankCrl(crlPath,
                        new KeyUtil().getPublicKey(PathUtils.R_CA_NODE_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_CA_NODE_PRI_KEY));
                break;

            case 6:
                String crlPath1 = "files/RSA/crl.crl";
                X509Certificate certificate = CerUtil.getCertificate(PathUtils.R_NODE_2_CER);
                new CrlUtil().addCertToCrl(certificate,crlPath1,
                        new KeyUtil().getPublicKey(PathUtils.R_CA_NODE_PUB_KEY),
                        new KeyUtil().getPrivateKey(PathUtils.R_CA_NODE_PRI_KEY));
                break;
        }



    }

    private static String readString() {
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

}
