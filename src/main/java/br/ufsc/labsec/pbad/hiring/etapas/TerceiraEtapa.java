package br.ufsc.labsec.pbad.hiring.etapas;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.TBSCertificate;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;

/**
 * <b>Terceira etapa - gerar certificados digitais</b>
 * <p>
 * Aqui você terá que gerar dois certificados digitais. A identidade ligada
 * a um dos certificados digitais deverá ser a sua. A entidade emissora do
 * seu certificado será a AC-Raiz, cuja chave privada já foi previamente
 * gerada. Também deverá ser feito o certificado digital para a AC-Raiz,
 * que deverá ser autoassinado.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * emitir um certificado digital autoassinado no formato X.509 para a AC-Raiz;
 * </li>
 * <li>
 * emitir um certificado digital no formato X.509, assinado pela AC-Raiz. O
 * certificado deve ter as seguintes características:
 * <ul>
 * <li>
 * {@code Subject} deverá ser o seu nome;
 * </li>
 * <li>
 * {@code SerialNumber} deverá ser o número da sua matrícula;
 * </li>
 * <li>
 * {@code Issuer} deverá ser a AC-Raiz.
 * </li>
 * </ul>
 * </li>
 * <li>
 * anexar ao desafio os certificados emitidos em formato PEM;
 * </li>
 * <li>
 * as chaves utilizadas nessa etapa deverão ser as mesmas já geradas.
 * </li>
 * </ul>
 */
public class TerceiraEtapa {

  public static void executarEtapa() {
    GeradorDeCertificados gerador = new GeradorDeCertificados();

    // Certificado AC-Raiz
    PublicKey chavePublicaAc = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaAc,
      Constantes.algoritmoChave);
    PrivateKey chavePrivadaAc = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc,
      Constantes.algoritmoChave);
    TBSCertificate certificadoTBSAc = gerador.gerarEstruturaCertificado(
      chavePublicaAc, Constantes.numeroSerieAc,
      Constantes.nomeAcRaiz, Constantes.nomeAcRaiz,
      365);
    DERBitString assinaturaAc = gerador.geraValorDaAssinaturaCertificado(certificadoTBSAc, chavePrivadaAc);
    X509Certificate certificadoAc = gerador.gerarCertificado(certificadoTBSAc, null, assinaturaAc);

    EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoAcRaiz, certificadoAc);

    // Certificado Usuário
    PublicKey chavePublicaUsuario = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaUsuario, 
      Constantes.algoritmoChave);
    TBSCertificate certificadoTBSUsuario = gerador.gerarEstruturaCertificado(
      chavePublicaUsuario, Constantes.numeroDeSerie, 
      Constantes.nomeUsuario, Constantes.nomeAcRaiz, 
      365);
    DERBitString assinaturaUsuario = gerador.geraValorDaAssinaturaCertificado(certificadoTBSUsuario, chavePrivadaAc);
    X509Certificate certificadoUsuario = gerador.gerarCertificado(certificadoTBSUsuario, null, assinaturaUsuario);

    EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoUsuario, certificadoUsuario);
  }

}
