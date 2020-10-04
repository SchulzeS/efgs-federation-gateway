/*-
 * ---license-start
 * EU-Federation-Gateway-Service / efgs-federation-gateway
 * ---
 * Copyright (C) 2020 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.interop.federationgateway.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.googlecode.protobuf.format.ProtobufFormatter;
import eu.interop.federationgateway.TestData;
import eu.interop.federationgateway.auditing.BatchAuditor;
import eu.interop.federationgateway.batchsigning.BatchSignatureUtils;
import eu.interop.federationgateway.batchsigning.BatchSignatureUtilsTest;
import eu.interop.federationgateway.batchsigning.BatchSignatureVerifier;
import eu.interop.federationgateway.batchsigning.SignatureGenerator;
import eu.interop.federationgateway.config.EfgsProperties;
import eu.interop.federationgateway.config.ProtobufConverter;
import eu.interop.federationgateway.entity.DiagnosisKeyEntity;
import eu.interop.federationgateway.filter.CertificateAuthentificationFilter;
import eu.interop.federationgateway.model.AuditEntry;
import eu.interop.federationgateway.model.EfgsProto;
import eu.interop.federationgateway.model.EfgsProto.DiagnosisKeyBatch;
import eu.interop.federationgateway.repository.CertificateRepository;
import eu.interop.federationgateway.repository.DiagnosisKeyBatchRepository;
import eu.interop.federationgateway.repository.DiagnosisKeyEntityRepository;
import eu.interop.federationgateway.service.DiagnosisKeyBatchService;
import eu.interop.federationgateway.testconfig.EfgsTestKeyStore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.security.cert.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@Slf4j
@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = EfgsTestKeyStore.class)
public class AuditControllerTest {

  private final ObjectMapper mapper = new ObjectMapper();
  @Autowired
  private WebApplicationContext context;
  @Autowired
  private EfgsProperties properties;
  @Autowired
  private DiagnosisKeyEntityRepository diagnosisKeyEntityRepository;
  @Autowired
  private CertificateRepository certificateRepository;
  @Autowired
  private CertificateAuthentificationFilter certFilter;
  @Autowired
  private DiagnosisKeyBatchService diagnosisKeyBatchService;
  @Autowired
  private DiagnosisKeyBatchRepository diagnosisKeyBatchRepository;
  private MockMvc mockMvc;
  private SignatureGenerator signatureGenerator;
  @Autowired
  private BatchAuditor batchAuditor;

  @Before
  public void setup() throws NoSuchAlgorithmException, CertificateException, IOException,
    OperatorCreationException, InvalidKeyException, SignatureException, KeyStoreException {
    signatureGenerator = new SignatureGenerator(certificateRepository);

    diagnosisKeyBatchRepository.deleteAll();
    diagnosisKeyEntityRepository.deleteAll();

    mockMvc = MockMvcBuilders
      .webAppContextSetup(context)
      .addFilter(certFilter)
      .build();
  }

  @Test
  public void testGetAuditInformation() throws Exception {
    ZonedDateTime currentDateTime = ZonedDateTime.now(ZoneOffset.UTC);
    String formattedDate = currentDateTime.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
    String batchTag = formattedDate + "-1";

    String batchSignature = createDiagnosisKeysTestData();
    MvcResult mvcResult =
      mockMvc.perform(get("/diagnosiskeys/audit/download/" + getDateString(currentDateTime) + "/" + batchTag)
        .accept(MediaType.APPLICATION_JSON_VALUE)
        .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE))
        .andExpect(status().isOk())
        .andReturn();

    String jsonResult = mvcResult.getResponse().getContentAsString();
    mapper.registerModule(new JavaTimeModule());
    List<AuditEntry> auditEntries = mapper.readValue(jsonResult, new TypeReference<>() {
    });

    X509Certificate trust_anchor= TestData.trustAnchor;
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    Signature signature = Signature.getInstance(trust_anchor.getSigAlgName(),"BC");
    signature.initVerify(trust_anchor.getPublicKey());


    Assert.assertEquals(1, auditEntries.size());
    AuditEntry auditEntry = auditEntries.get(0);
    Assert.assertEquals("DE", auditEntry.getCountry());
    Assert.assertEquals(3, auditEntry.getAmount());
    Assert.assertEquals(TestData.AUTH_CERT_HASH, auditEntry.getUploaderThumbprint());
    Assert.assertNotNull(auditEntry.getUploaderCertificate());
    Assert.assertNotNull(auditEntry.getUploaderOperatorSignature());
    signature.update(auditEntry.getUploaderCertificate().getBytes());
    Assert.assertTrue(signature.verify(Base64.getDecoder().decode(auditEntry.getUploaderOperatorSignature().getBytes())));
    Assert.assertNotNull(auditEntry.getSigningCertificate());
    Assert.assertNotNull(auditEntry.getSigningCertificateOperatorSignature());
    signature.update(auditEntry.getSigningCertificate().getBytes());
    Assert.assertTrue(signature.verify(Base64.getDecoder().decode(auditEntry.getSigningCertificateOperatorSignature().getBytes())));
    Assert.assertEquals(batchSignature, auditEntry.getBatchSignature());
  }

  @Test
  public void testRequestShouldFailIfBatchTagDoesNotExists() throws Exception {
    ZonedDateTime currentDateTime = ZonedDateTime.now(ZoneOffset.UTC);
    String formattedDate = currentDateTime.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
    String batchTag = formattedDate + "-1";

    mockMvc.perform(
      get("/diagnosiskeys/audit/download/" + getDateString(currentDateTime) + "/" + batchTag)
        .accept(MediaType.APPLICATION_JSON_VALUE)
        .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE))
      .andExpect(status().isNotFound());
  }

  @Test
  public void testRequestShouldFailIfNoEntityExistForDate() throws Exception {
    ZonedDateTime currentDateTime = ZonedDateTime.now(ZoneOffset.UTC).minusDays(1);
    String formattedDate = currentDateTime.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
    String batchTag = formattedDate + "-1";

    createDiagnosisKeysTestData();
    List<DiagnosisKeyEntity> all = diagnosisKeyEntityRepository.findAll();
    mockMvc.perform(
      get("/diagnosiskeys/audit/download/" + getDateString(currentDateTime) + "/" + batchTag)
        .accept(MediaType.APPLICATION_JSON_VALUE)
        .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE))
      .andExpect(status().isNotFound());
  }

  @Test
  public void testAudit() throws Exception
  {
    ZonedDateTime timestampBatchTag = ZonedDateTime.now(ZoneOffset.UTC);
     var signatures= createDiagnosisMultipleKeyBatches();

     MvcResult downloadresult= mockMvc.perform(get("/diagnosiskeys/download/" + getDateString(timestampBatchTag))
      .accept("application/protobuf; version=1.0")
      .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH_FOREIGN)
      .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_foreign)
    )
    .andExpect(status().isOk())
    .andReturn();

    String batchTag= downloadresult.getResponse().getHeader("batchTag");
  
    MvcResult auditResult =
    mockMvc.perform(get("/diagnosiskeys/audit/download/" + getDateString(timestampBatchTag) + "/" + batchTag)
      .accept(MediaType.APPLICATION_JSON_VALUE)
      .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH_FOREIGN)
      .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_foreign))
      .andExpect(status().isOk())
      .andReturn();

    EfgsProto.DiagnosisKeyBatch downloadedBatch = EfgsProto.DiagnosisKeyBatch.parseFrom(
      downloadresult.getResponse().getContentAsByteArray());

    String jsonResult = auditResult.getResponse().getContentAsString();
    mapper.registerModule(new JavaTimeModule());
    List<AuditEntry> auditEntries = mapper.readValue(jsonResult, new TypeReference<>() {
    });

    int sigIdx=0;
    for(AuditEntry auditEntry:auditEntries)
    {
        Assert.assertEquals(auditEntry.getBatchSignature(), signatures.get(sigIdx));
        sigIdx++;
    }
 
    Assert.assertTrue(batchAuditor.auditBatch(downloadedBatch,auditEntries,TestData.trustAnchor));


  }

  @Test
  public void testRequestShouldFailIfDateExpired() throws Exception {
    ZonedDateTime currentDateTime = ZonedDateTime.now(ZoneOffset.UTC).minusMonths(2);

    mockMvc.perform(
      get("/diagnosiskeys/audit/download/" + getDateString(currentDateTime) + "/" + TestData.SECOND_BATCHTAG)
        .accept(MediaType.APPLICATION_JSON_VALUE)
        .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
        .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE))
      .andExpect(status().isGone());
  }

  private String createDiagnosisKeysTestData() throws Exception {
    EfgsProto.DiagnosisKey key1 = TestData.getDiagnosisKeyProto().toBuilder().setTransmissionRiskLevel(3).build();
    EfgsProto.DiagnosisKey key2 = TestData.getDiagnosisKeyProto().toBuilder().setTransmissionRiskLevel(4).build();
    EfgsProto.DiagnosisKey key3 = TestData.getDiagnosisKeyProto().toBuilder().setTransmissionRiskLevel(5).build();

    EfgsProto.DiagnosisKeyBatch batch = EfgsProto.DiagnosisKeyBatch.newBuilder().addAllKeys(Arrays.asList(key1,
      key2, key3)).build();

    byte[] bytesToSign = BatchSignatureUtilsTest.createBytesToSign(batch);
    String signature = signatureGenerator.sign(bytesToSign, TestData.validCertificate);

    ProtobufFormatter formatter = new ProtobufConverter();
    String jsonFormatted = formatter.printToString(batch);

    log.info("Json Formatted Payload: {}", jsonFormatted);

    mockMvc.perform(post("/diagnosiskeys/upload")
      .contentType("application/protobuf; version=1.0")
      .header("batchTag", TestData.FIRST_BATCHTAG)
      .header("batchSignature", signature)
      .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
      .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE)
      .content(batch.toByteArray()))
      .andExpect(status().isCreated());

    diagnosisKeyBatchService.batchDocuments();
    return signature;
  }

  private List<String> createDiagnosisMultipleKeyBatches() throws Exception {
    EfgsProto.DiagnosisKey key1 = TestData.getDiagnosisKeyProto().toBuilder().setTransmissionRiskLevel(3).build();
    EfgsProto.DiagnosisKey key2 = TestData.getDiagnosisKeyProto().toBuilder().setTransmissionRiskLevel(4).build();
    EfgsProto.DiagnosisKey key3 = TestData.getDiagnosisKeyProto().toBuilder().setTransmissionRiskLevel(5).build();
    EfgsProto.DiagnosisKey key4 = TestData.getDiagnosisKeyProto().toBuilder().setRollingPeriod(55).setTransmissionRiskLevel(5).build();
    EfgsProto.DiagnosisKey key5 = TestData.getDiagnosisKeyProto().toBuilder().setRollingPeriod(11).setTransmissionRiskLevel(5).build();
    EfgsProto.DiagnosisKey key6 = TestData.getDiagnosisKeyProto().toBuilder().setRollingPeriod(15).setTransmissionRiskLevel(5).build();
    EfgsProto.DiagnosisKeyBatch batch = EfgsProto.DiagnosisKeyBatch.newBuilder().addAllKeys(Arrays.asList(key1,
      key2, key3)).build();

    EfgsProto.DiagnosisKeyBatch batch2 = EfgsProto.DiagnosisKeyBatch.newBuilder().addAllKeys(Arrays.asList(key4)).build();

    EfgsProto.DiagnosisKeyBatch batch3 = EfgsProto.DiagnosisKeyBatch.newBuilder().addAllKeys(Arrays.asList(key5,
    key6)).build();

    byte[] bytesToSign = BatchSignatureUtilsTest.createBytesToSign(batch);
    byte[] bytesToSign2 = BatchSignatureUtilsTest.createBytesToSign(batch2);
    byte[] bytesToSign3 = BatchSignatureUtilsTest.createBytesToSign(batch3);

    String signature = signatureGenerator.sign(bytesToSign, TestData.validCertificate);
    String signature2 = signatureGenerator.sign(bytesToSign2, TestData.validCertificate);
    String signature3 = signatureGenerator.sign(bytesToSign3, TestData.validCertificate);

    ProtobufFormatter formatter = new ProtobufConverter();
    String jsonFormatted = formatter.printToString(batch);

    String jsonFormatted3 = formatter.printToString(batch3);

    log.info("Json Formatted Payload: {}", jsonFormatted3);
    try
    {
      mockMvc.perform(post("/diagnosiskeys/upload")
      .contentType("application/protobuf; version=1.0")
      .header("batchTag", "Batch")
      .header("batchSignature", signature3)
      .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
      .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE)
      .content(batch3.toByteArray()))
      .andExpect(status().isCreated());
    }
    catch(Exception e)
    {
        Assert.fail();
    }


    log.info("Json Formatted Payload: {}", jsonFormatted);
    try
    {
      mockMvc.perform(post("/diagnosiskeys/upload")
      .contentType("application/protobuf; version=1.0")
      .header("batchTag", TestData.FIRST_BATCHTAG)
      .header("batchSignature", signature)
      .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
      .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE)
      .content(batch.toByteArray()))
      .andExpect(status().isCreated());
    }
    catch(Exception e)
    {
        Assert.fail();
    }

    String jsonFormatted2 = formatter.printToString(batch2);

    log.info("Json Formatted Payload: {}", jsonFormatted2);
    try
    {
      mockMvc.perform(post("/diagnosiskeys/upload")
      .contentType("application/protobuf; version=1.0")
      .header("batchTag", TestData.SECOND_BATCHTAG)
      .header("batchSignature", signature2)
      .header(properties.getCertAuth().getHeaderFields().getThumbprint(), TestData.AUTH_CERT_HASH)
      .header(properties.getCertAuth().getHeaderFields().getDistinguishedName(), TestData.DN_STRING_DE)
      .content(batch2.toByteArray()))
      .andExpect(status().isCreated());
    }
    catch(Exception e)
    {
        Assert.fail();
    }
     
    diagnosisKeyBatchService.batchDocuments();
    return List.of(signature3,signature,signature2);
  }

  private static String getDateString(ZonedDateTime timestamp) {
    return timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE);
  }
}
