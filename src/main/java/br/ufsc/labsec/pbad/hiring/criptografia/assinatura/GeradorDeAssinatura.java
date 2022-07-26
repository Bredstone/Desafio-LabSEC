package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Classe responsável por gerar uma assinatura digital.
 * <p>
 * Aqui será necessário usar a biblioteca Bouncy Castle, pois ela já possui a
 * estrutura básica da assinatura implementada.
 */
public class GeradorDeAssinatura {

  private X509Certificate certificado;
  private PrivateKey chavePrivada;
  private CMSSignedDataGenerator geradorAssinaturaCms;

  /**
   * Construtor.
   */
  public GeradorDeAssinatura() {
    geradorAssinaturaCms = new CMSSignedDataGenerator();
  }

  /**
   * Informa qual será o assinante.
   *
   * @param certificado  certificado, no padrão X.509, do assinante.
   * @param chavePrivada chave privada do assinante.
   */
  public void informaAssinante(X509Certificate certificado,
      PrivateKey chavePrivada) {
    this.certificado = certificado;
    this.chavePrivada = chavePrivada;
  }

  /**
   * Gera uma assinatura no padrão CMS.
   *
   * @param caminhoDocumento caminho do documento que será assinado.
   * @return Documento assinado.
   */
  public CMSSignedData assinar(String caminhoDocumento) {
    try {
      CMSTypedData msg = this.preparaDadosParaAssinar(caminhoDocumento);
      
      List<X509Certificate> certList = new ArrayList<>();
      certList.add(certificado);

      geradorAssinaturaCms.addSignerInfoGenerator(this.preparaInformacoesAssinante(chavePrivada, certificado));
      geradorAssinaturaCms.addCertificates(new JcaCertStore(certList));

      return geradorAssinaturaCms.generate(msg, true);
    } catch (CMSException | CertificateEncodingException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Transforma o documento que será assinado para um formato compatível
   * com a assinatura.
   *
   * @param caminhoDocumento caminho do documento que será assinado.
   * @return Documento no formato correto.
   */
  private CMSTypedData preparaDadosParaAssinar(String caminhoDocumento) {
    try {
      String textoPlano = Files.readString(new File(caminhoDocumento).toPath());
      return new CMSProcessableByteArray(textoPlano.getBytes());
    } catch (IOException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Gera as informações do assinante na estrutura necessária para ser
   * adicionada na assinatura.
   *
   * @param chavePrivada chave privada do assinante.
   * @param certificado  certificado do assinante.
   * @return Estrutura com informações do assinante.
   */
  private SignerInfoGenerator preparaInformacoesAssinante(PrivateKey chavePrivada,
      Certificate certificado) {
    try {
      ContentSigner sha256Signer = new JcaContentSignerBuilder(Constantes.algoritmoAssinatura).build(chavePrivada);
      return new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha256Signer, (X509Certificate) certificado);
    } catch (CertificateEncodingException | OperatorCreationException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Escreve a assinatura no local apontado.
   *
   * @param arquivo    arquivo que será escrita a assinatura.
   * @param assinatura objeto da assinatura.
   */
  public void escreveAssinatura(OutputStream arquivo, CMSSignedData assinatura) {
    try {
      arquivo.write(assinatura.getEncoded(ASN1Encoding.DER));
      arquivo.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}
