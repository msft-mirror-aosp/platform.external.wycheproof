/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.Ignore;
import android.security.keystore.KeyProtection;
import android.security.keystore.KeyProperties;
import android.keystore.cts.util.KeyStoreUtil;
import android.util.Log;

/** This test uses test vectors in JSON format to check implementations of ECDH. */
public class JsonEcdhTest {
  private static final String TAG = "JsonEcdhTest";
  private static final String EXPECTED_PROVIDER_NAME = TestUtil.EXPECTED_PROVIDER_NAME;
  private static final String KEY_ALIAS_1 = "Key1";

  @After
  public void tearDown() throws Exception {
    KeyStoreUtil.cleanUpKeyStore();
  }

  @Before
  public void setup() {
    // In this test class ECDH keys are imported for key agreement (PURPOSE_AGREE_KEY).
    // KeyMaster could support this key import through software emulation,
    // but currently it is missing (b/216434270). Hence, this assumption is added till ECDH
    // key import software emulation is not implemented.
    assumeTrue("PURPOSE_AGREE_KEY is supported in KeyMint version 1 and above.",
            KeyStoreUtil.getFeatureVersionKeystore() >= KeyStoreUtil.KM_VERSION_KEYMINT_1);
  }

  /** Convenience mehtod to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a BigInteger from a JsonObject */
  protected static BigInteger getBigInteger(JsonObject object, String name) throws Exception {
    return JsonUtil.asBigInteger(object.get(name));
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Example for test vector
   * {
   * "algorithm" : "ECDH",
   * "header" : [],
   * "notes" : {
   *   "AddSubChain" : "The private key has a special value....",
   * }
   * "generatorVersion" : "0.7",
   * "numberOfTests" : 308,
   * "testGroups" : [
   *   {
   *     "type" : "EcdhTest",
   *     "tests" : [
   *        {
   *         "comment" : "normal case",
   *         "curve" : "secp224r1",
   *         "private" : "565577a49415ca761a0322ad54e4ad0ae7625174baf372c2816f5328",
   *         "public" : "30...",
   *         "result" : "valid",
   *         "shared" : "b8ecdb552d39228ee332bafe4886dbff272f7109edf933bc7542bd4f",
   *         "tcId" : 1
   *        },
   *     ...
   **/
  public void testEcdhComp(String filename) throws Exception {
    testEcdhComp(filename, false);
  }
  public void testEcdhComp(String filename, boolean isStrongBox) throws Exception {
    JsonObject test = JsonUtil.getTestVectors(this.getClass(), filename);

    // This test expects test vectors as defined in wycheproof/schemas/ecdh_test_schema.json.
    // In particular, this means that the public keys use X509 encoding.
    // Test vectors with different encodings of the keys have a different schema.
    final String expectedSchema = "ecdh_test_schema.json";
    String schema = test.get("schema").getAsString();
    assertEquals("Unexpected schema in file:" + filename, expectedSchema, schema);

    int numTests = test.get("numberOfTests").getAsInt();
    int passedTests = 0;
    int rejectedTests = 0;  // invalid test vectors leading to exceptions
    int skippedTests = 0;  // valid test vectors leading to exceptions
    int errors = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      String curve = getString(group, "curve");
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String comment = getString(testcase, "comment");
        BigInteger priv = getBigInteger(testcase, "private");
        byte[] publicEncoded = getBytes(testcase, "public");
        String result = getString(testcase, "result");
        String expectedHex = getString(testcase, "shared");
        KeyFactory kf = KeyFactory.getInstance("EC");
        try {
          ECPrivateKeySpec spec = new ECPrivateKeySpec(priv, EcUtil.getCurveSpecRef(curve));
          PrivateKey privKey = kf.generatePrivate(spec);
          X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(publicEncoded);
          PublicKey pubKey = kf.generatePublic(x509keySpec);

          KeyStore keyStore = KeyStoreUtil.saveKeysToKeystore(KEY_ALIAS_1, pubKey, privKey,
                                 new KeyProtection.Builder(KeyProperties.PURPOSE_AGREE_KEY)
                                 .setIsStrongBoxBacked(isStrongBox)
                                 .build());
          KeyAgreement ka = KeyAgreement.getInstance("ECDH", EXPECTED_PROVIDER_NAME);
          PrivateKey keyStorePrivateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS_1, null);
          PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS_1).getPublicKey();

          ka.init(keyStorePrivateKey);
          ka.doPhase(publicKey, true);
          String sharedHex = TestUtil.bytesToHex(ka.generateSecret());
          if (result.equals("invalid")) {
            Log.e(TAG,
                "Computed ECDH with invalid parameters"
                    + " tcId:"
                    + tcid
                    + " comment:"
                    + comment
                    + " shared:"
                    + sharedHex);
            errors++;
          } else if (!expectedHex.equals(sharedHex)) {
            Log.e(TAG,
                "Incorrect ECDH computation"
                    + " tcId:"
                    + tcid
                    + " comment:"
                    + comment
                    + "\nshared:"
                    + sharedHex
                    + "\nexpected:"
                    + expectedHex);
            errors++;
          } else {
            passedTests++;
          }
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException ex) {
          Log.e(TAG,
                  "Test vector with tcId:" + tcid + " comment:" + comment + " throws:" + ex.toString());
          // These are the exception that we expect to see when a curve is not implemented
          // or when a key is not valid.
          if (result.equals("valid")) {
            skippedTests++;
          } else {
            rejectedTests++;
          }
        } catch (Exception ex) {
          // Other exceptions typically indicate that something is wrong with the implementation.
          Log.e(TAG,
              "Test vector with tcId:" + tcid + " comment:" + comment + " throws:" + ex.toString());
          errors++;
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, passedTests + rejectedTests);
  }

  @Test
  public void testSecp224r1() throws Exception {
    testEcdhComp("ecdh_secp224r1_test.json");
  }

  @Test
  public void testSecp256r1() throws Exception {
    testEcdhComp("ecdh_secp256r1_test.json");
  }
  @Test
  @Ignore //TODO Reverify after bug b/215175472 is fixed.
  public void testSecp256r1_StrongBox() throws Exception {
    KeyStoreUtil.assumeStrongBox();
    testEcdhComp("ecdh_secp256r1_test.json", true);
  }

  @Test
  public void testSecp384r1() throws Exception {
    testEcdhComp("ecdh_secp384r1_test.json");
  }

  @Test
  public void testSecp521r1() throws Exception {
    testEcdhComp("ecdh_secp521r1_test.json");
  }

  @Test
  @Ignore // Secp256k1 curve not supported in AndroidKeystore
  public void testSecp256k1() throws Exception {
    testEcdhComp("ecdh_secp256k1_test.json");
  }

  @Test
  @Ignore // Brainpool curves are not supported in AndroidKeystore
  public void testBrainpoolP224r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP224r1_test.json");
  }

  @Test
  @Ignore // Brainpool curves are not supported in AndroidKeystore
  public void testBrainpoolP256r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP256r1_test.json");
  }

  @Test
  @Ignore // Brainpool curves are not supported in AndroidKeystore
  public void testBrainpoolP320r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP320r1_test.json");
  }

  @Test
  @Ignore // Brainpool curves are not supported in AndroidKeystore
  public void testBrainpoolP384r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP384r1_test.json");
  }

  @Test
  @Ignore // Brainpool curves are not supported in AndroidKeystore
  public void testBrainpoolP512r1() throws Exception {
    testEcdhComp("ecdh_brainpoolP512r1_test.json");
  }

}
