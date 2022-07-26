package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import br.ufsc.labsec.pbad.hiring.Constantes;

/**
 * Essa classe representa um repositório de chaves do tipo PKCS#12.
 *
 * @see KeyStore
 */
public class RepositorioChaves {

  private KeyStore repositorio;
  private char[] senha;
  private String alias;

  /**
   * Construtor.
   */
  public RepositorioChaves() {
    try {
      this.repositorio = KeyStore.getInstance(Constantes.formatoRepositorio);
    } catch (KeyStoreException e) {
      e.printStackTrace();
    }
  }

  /**
   * Abre o repositório do local indicado.
   *
   * @param caminhoRepositorio caminho do PKCS#12.
   * @param alias nome amigável dado à entrada do PKCS#12.
   * @param senha senha de acesso ao PKCS#12.
   */
  public void abrir(String caminhoRepositorio, String alias, char[] senha) {
    try {
      this.alias = alias;
      this.senha = senha;
      this.repositorio.load(new FileInputStream(caminhoRepositorio), senha);
    } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Obtém a chave privada do PKCS#12.
   * 
   * @return Chave privada.
   */
  public PrivateKey pegarChavePrivada() {
    try {
      return (PrivateKey) this.repositorio.getKey(this.alias, this.senha);
    } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Obtém do certificado do PKCS#12.
   *
   * @return Certificado.
   */
  public X509Certificate pegarCertificado() {
    try {
      return (X509Certificate) this.repositorio.getCertificateChain(this.alias)[0];
    } catch (KeyStoreException e) {
      e.printStackTrace();
      return null;
    }
  }

}
