package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.cert.X509Certificate;

/**
 * Classe responsável por verificar a integridade de uma assinatura.
 */
public class VerificadorDeAssinatura {

  /**
   * Verifica a integridade de uma assinatura digital no padrão CMS.
   *
   * @param certificado certificado do assinante.
   * @param assinatura  documento assinado.
   * @return {@code true} se a assinatura for íntegra, e {@code false} do
   *         contrário.
   */
  public boolean verificarAssinatura(X509Certificate certificado, CMSSignedData assinatura) {
    try {
      SignerInformation infoAssinatura = this.pegaInformacoesAssinatura(assinatura);
      SignerInformationVerifier verificador = this.geraVerificadorInformacoesAssinatura(certificado);
      return infoAssinatura.verify(verificador);
    } catch (CMSException e) {
      e.printStackTrace();
      return false;
    }
  }

  /**
   * Gera o verificador de assinaturas a partir das informações do assinante.
   *
   * @param certificado certificado do assinante.
   * @return Objeto que representa o verificador de assinaturas.
   */
  private SignerInformationVerifier geraVerificadorInformacoesAssinatura(X509Certificate certificado) {
    try {
      ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(certificado);
      DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(new BouncyCastleProvider()).build();
      SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
      CMSSignatureAlgorithmNameGenerator signatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
      
      return new SignerInformationVerifier(signatureAlgorithmNameGenerator, signatureAlgorithmIdentifierFinder, contentVerifierProvider, digestCalculatorProvider);
    } catch (OperatorCreationException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Classe responsável por pegar as informações da assinatura dentro do CMS.
   *
   * @param assinatura documento assinado.
   * @return Informações da assinatura.
   */
  private SignerInformation pegaInformacoesAssinatura(CMSSignedData assinatura) {
    return (SignerInformation) assinatura.getSignerInfos().getSigners().toArray()[0];
  }

}
