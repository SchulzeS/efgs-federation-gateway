package eu.interop.federationgateway.auditing;

import eu.interop.federationgateway.batchsigning.BatchSignatureVerifier;
import eu.interop.federationgateway.model.AuditEntry;
import eu.interop.federationgateway.model.EfgsProto;
import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * This class contains the methods to verify a batch signature.
 */
@Slf4j
@Service
public class BatchAuditor  {

  private BatchSignatureVerifier verifier;

  public BatchAuditor(BatchSignatureVerifier verifier) {
    this.verifier = verifier;
  }

  /**
   * Audits a downloaded batch by the given audit entries.
   *
   * @param downloadedBatch Downloaded Batch.
   * @param auditEntries Audit Entries downloaded for the batch.
   * @param trustAnchorCertificate  Public key of the trust anchor.
   * @return true if the Audit was successfull.
   */
  public boolean auditBatch(EfgsProto.DiagnosisKeyBatch downloadedBatch,List<AuditEntry> auditEntries,
                                                                        X509Certificate trustAnchorCertificate)
    throws SignatureException, 
           InvalidKeyException,
           NoSuchAlgorithmException,
           NoSuchProviderException,
           CertificateException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    int idx = 0;
    boolean valid = true;
    for (AuditEntry auditEntry:auditEntries) {
      List<EfgsProto.DiagnosisKey> keys = new ArrayList<>();
    
      for (int i = 0; i < auditEntry.getAmount(); i++) {
        keys.add(downloadedBatch.getKeys(i + idx));
      }
        
      idx += auditEntry.getAmount();

      EfgsProto.DiagnosisKeyBatch batch = EfgsProto.DiagnosisKeyBatch.newBuilder().addAllKeys(keys).build();

      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      
      X509Certificate signerCertificate = 
                      (X509Certificate) certificateFactory
                                        .generateCertificate(
                                            new ByteArrayInputStream(
                                                auditEntry.getSigningCertificate().getBytes()));

      valid &= verifier.checkBatchSignature(batch,
                                   auditEntry.getBatchSignature(),
                                   signerCertificate).equals(auditEntry.getUploaderSigningThumbprint());
    
      Signature signature = Signature.getInstance(trustAnchorCertificate.getSigAlgName(),"BC");
      signature.initVerify(trustAnchorCertificate.getPublicKey());
      signature.update(auditEntry.getSigningCertificate().getBytes());
      valid &= signature.verify(Base64.getDecoder()
                                      .decode(auditEntry.getSigningCertificateOperatorSignature().getBytes()));  
    }
    return valid;
  }

  /**
   * Audits the Signature of an batch.
   *
   * @param batch Diagnosiskey Batch.
   * @param signature  Given signature to the batch.
   * @return true if the Audit was successfull.
   */
  public boolean auditBatch(EfgsProto.DiagnosisKeyBatch batch, String signature) {
    return verifier.checkBatchSignature(batch,signature) != null;
  }
}
