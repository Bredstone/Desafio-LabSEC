package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import br.ufsc.labsec.pbad.hiring.Constantes;

/**
 * Classe responsável por gerar certificados no padrão X.509.
 * <p>
 * Um certificado é basicamente composto por três partes, que são:
 * <ul>
 * <li>
 * Estrutura de informações do certificado;
 * </li>
 * <li>
 * Algoritmo de assinatura;
 * </li>
 * <li>
 * Valor da assinatura.
 * </li>
 * </ul>
 */

public class GeradorDeCertificados {

  /**
   * Gera a estrutura de informações de um certificado.
   *
   * @param chavePublica  chave pública do titular.
   * @param numeroDeSerie número de série do certificado.
   * @param nome          nome do titular.
   * @param nomeAc        nome da autoridade emissora.
   * @param dias          a partir da data atual, quantos dias de validade
   *                      terá o certificado.
   * @return Estrutura de informações do certificado.
   */
  public TBSCertificate gerarEstruturaCertificado(PublicKey chavePublica,
      int numeroDeSerie, String nome,
      String nomeAc, int dias) {
    Date startDate = new Date();
    Date endDate = new Date();
    Calendar c = Calendar.getInstance(); 
    c.setTime(endDate); 
    c.add(Calendar.DATE, dias);
    endDate = c.getTime();

    V3TBSCertificateGenerator tbsBuilder = new V3TBSCertificateGenerator();
    tbsBuilder.setIssuer(new X500Name(nomeAc));
    tbsBuilder.setSerialNumber(new ASN1Integer(BigInteger.valueOf(numeroDeSerie)));
    tbsBuilder.setStartDate(new ASN1UTCTime(startDate));
    tbsBuilder.setEndDate(new ASN1UTCTime(endDate));
    tbsBuilder.setSubject(new X500Name(nome));
    tbsBuilder.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(chavePublica.getEncoded()));

    DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
    tbsBuilder.setSignature(finder.find(Constantes.algoritmoAssinatura));
    
    return tbsBuilder.generateTBSCertificate();
  }

  /**
   * Gera valor da assinatura do certificado.
   *
   * @param estruturaCertificado estrutura de informações do certificado.
   * @param chavePrivadaAc       chave privada da AC que emitirá esse
   *                             certificado.
   * @return Bytes da assinatura.
   */
  public DERBitString geraValorDaAssinaturaCertificado(TBSCertificate estruturaCertificado,
      PrivateKey chavePrivadaAc) {
    try {
      Signature sig = Signature.getInstance(Constantes.algoritmoAssinatura);
      sig.initSign(chavePrivadaAc);
      sig.update(estruturaCertificado.getEncoded(ASN1Encoding.DER));

      return new DERBitString(sig.sign());
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
      e.printStackTrace();

      return null;
    }
  }

  /**
   * Gera um certificado.
   *
   * @param estruturaCertificado  estrutura de informações do certificado.
   * @param algoritmoDeAssinatura algoritmo de assinatura.
   * @param valorDaAssinatura     valor da assinatura.
   * @return Objeto que representa o certificado.
   * @see ASN1EncodableVector
   */
  public X509Certificate gerarCertificado(TBSCertificate estruturaCertificado,
      AlgorithmIdentifier algoritmoDeAssinatura, DERBitString valorDaAssinatura) {
    try {
      ASN1EncodableVector v = new ASN1EncodableVector();

      v.add(estruturaCertificado);
      v.add(estruturaCertificado.getSignature());
      v.add(valorDaAssinatura);

      DERSequence derSequence = new DERSequence(v);
      ByteArrayInputStream baos = new ByteArrayInputStream(derSequence.getEncoded());
      return (X509Certificate) CertificateFactory.getInstance(Constantes.formatoCertificado).generateCertificate(baos);
    } catch (CertificateException | IOException e) {
      e.printStackTrace();
      return null;
    }
  }

}
