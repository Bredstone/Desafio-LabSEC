package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PrivateKey;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

/**
 * Essa classe é responsável por escrever uma chave assimétrica no disco. Note
 * que a chave pode ser tanto uma chave pública quanto uma chave privada.
 *
 * @see Key
 */
public class EscritorDeChaves {

  /**
   * Escreve uma chave no local indicado.
   *
   * @param chave         chave assimétrica a ser escrita em disco.
   * @param nomeDoArquivo nome do local onde será escrita a chave.
   */
  public static void escreveChaveEmDisco(Key chave, String nomeDoArquivo) {
    try {
      StringWriter stringWriter = new StringWriter();
      JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
      if (chave.getFormat() == "PKCS#8") {
        pemWriter.writeObject(new JcaPKCS8Generator((PrivateKey) chave, null));
      } else {
        pemWriter.writeObject(chave);
      }
      pemWriter.close();
      Files.write(Paths.get(nomeDoArquivo), stringWriter.toString().getBytes());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}
