package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.FileReader;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

/**
 * Classe responsável por ler um certificado do disco.
 *
 * @see CertificateFactory
 */
public class LeitorDeCertificados {

  /**
   * Lê um certificado do local indicado.
   *
   * @param caminhoCertificado caminho do certificado a ser lido.
   * @return Objeto do certificado.
   */
  public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado) {
    try {
      FileReader certReader = new FileReader(caminhoCertificado);

      PEMParser pemParser = new PEMParser(certReader);
      JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
      Object certificado = pemParser.readObject();
      pemParser.close();

      return converter.getCertificate((X509CertificateHolder) certificado);
    } catch (IOException | CertificateException e) {
      e.printStackTrace();
      return null;
    }
  }

}
