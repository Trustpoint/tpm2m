package ca.trustpoint.m2m.ecqv;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.trustpoint.m2m.KeyAlgorithmDefinition;
import ca.trustpoint.m2m.M2mSignatureAlgorithmOids;
import ca.trustpoint.m2m.SignatureAlgorithms;

public class EcqvProviderTest {
  @BeforeClass
  public static void initializeTests() {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * In trying to test the M2mCertificates reconstructPrivateKey() method it became apparent it was
   * not trivial to find the CAs ephemeralPrivateKey. These tests work with the EcqvProvider class
   * directly (which M2mCertificate uses for verification)
   *
   * Test method for {@link ca.trustpoint.m2m.ecqv.EcqvProvider#reconstructPublicKey}
   * {@link ca.trustpoint.m2m.ecqv.EcqvProvider#reconstructPrivateKey}
   * {@link ca.trustpoint.m2m.ecqv.EcqvProvider#verifyKeyPair}
   */
  @Test
  public void testReconstructionData() throws Exception {
    // simulate a certificate generated from the CA
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
    g.initialize(ecSpec, new SecureRandom());
    KeyPair pair = g.generateKeyPair();

    // simulate a CA certificate
    KeyPair caKeyPair = g.generateKeyPair();

    KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
    caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

    SignatureAlgorithms caAlgorithm =
        SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());

    // hash of tbs certificate
    byte[] tbsCertificate = {0x01};

    EcqvProvider provider = new EcqvProvider(caAlgorithm, caKeyDefinition.getParameters());
    KeyReconstructionData keyReconData =
        provider.genReconstructionData(tbsCertificate, pair.getPublic(), caKeyPair.getPrivate());

    // reconstruct publicKey
    PublicKey reconstructedPublicKey = provider.reconstructPublicKey(tbsCertificate,
        keyReconData.getPublicKeyReconstructionData(), caKeyPair.getPublic());

    // reconstruct privateKey
    PrivateKey reconstructedPrivateKey = provider.reconstructPrivateKey(tbsCertificate,
        keyReconData.getPublicKeyReconstructionData(),
        keyReconData.getPrivateKeyReconstructionData(), pair.getPrivate());

    /*
     * using the reconstructed public and private key sign data[] with reconstructedPrivateKey and
     * verify with the reconstructedPublicKey
     */
    byte[] data = "data".getBytes("UTF8");

    Signature sig = Signature.getInstance("ECDSA");
    sig.initSign(reconstructedPrivateKey);
    sig.update(data);
    byte[] signatureBytes = sig.sign();

    sig.initVerify(reconstructedPublicKey);
    sig.update(data);

    assertTrue(sig.verify(signatureBytes));

    // test verifyKeyPair
    assertTrue(provider.verifyKeyPair(reconstructedPublicKey, reconstructedPrivateKey));
  }
}
