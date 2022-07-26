package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Classe responsável por escrever um certificado no disco.
 */
public class EscritorDeCertificados {

  /**
   * Escreve o certificado indicado no disco.
   *
   * @param nomeArquivo caminho que será escrito o certificado.
   * @param certificado objeto que representa o certificado.
   */
  public static void escreveCertificado(String nomeArquivo,
      X509Certificate certificado) {
    try {
      StringWriter stringWriter = new StringWriter();
      JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
      pemWriter.writeObject(certificado);
      pemWriter.close();
      Files.write(Paths.get(nomeArquivo), stringWriter.toString().getBytes());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}
