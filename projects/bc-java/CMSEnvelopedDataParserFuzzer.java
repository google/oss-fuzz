// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;

public class CMSEnvelopedDataParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    X509Certificate _reciCert;
    String _signDN   = "O=Bouncy Castle, C=AU";
    KeyPair _signKP   = CMSTestUtil.makeKeyPair();
    String _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
    KeyPair _reciKP   = CMSTestUtil.makeKeyPair();
    try{
	    _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
    }
    catch(GeneralSecurityException | IOException | OperatorCreationException e){
    	return;
    }
  
    try{
      CMSTypedData msg     = new CMSProcessableByteArray(data.consumeRemainingAsBytes());
      CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
      
      try{
	      edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider("BC")) ;
      }
      catch(CertificateEncodingException e){
      	return;
      }
      
      CMSEnvelopedData ed = edGen.generate(
                                        msg,
                                        new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
                                           .setProvider("BC").build());
      CMSEnvelopedDataParser cedp = new CMSEnvelopedDataParser(ed.getEncoded());
      cedp.getEncryptionAlgParams();      
    }
      catch (CMSException | IOException e){
        return;
    }
  }
}
