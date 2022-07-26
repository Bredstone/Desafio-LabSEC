package br.ufsc.labsec.pbad.hiring.criptografia.resumo;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import br.ufsc.labsec.pbad.hiring.Constantes;

/**
 * Classe responsável por executar a função de resumo criptográfico.
 *
 * @see MessageDigest
 */
public class Resumidor {

  private MessageDigest md;
  private String algoritmo;

  /**
   * Construtor.
   */
  public Resumidor() {
    try {
      this.algoritmo = Constantes.algoritmoResumo;    // Algoritmo para gerar o resumo criptográfico
      this.md = MessageDigest.getInstance(algoritmo);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  /**
   * Calcula o resumo criptográfico do arquivo indicado.
   *
   * @param arquivoDeEntrada arquivo a ser processado.
   * @return Bytes do resumo.
   */
  public byte[] resumir(File arquivoDeEntrada) {
    try {
      String textoPlano = Files.readString(arquivoDeEntrada.toPath());
      return this.md.digest(textoPlano.getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Escreve o resumo criptográfico no local indicado.
   *
   * @param resumo         resumo criptográfico em bytes.
   * @param caminhoArquivo caminho do arquivo.
   */
  public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) {
    try {
      BigInteger bi = new BigInteger(1, resumo);
      String resumoHex = String.format("%0" + (resumo.length << 1) + "x", bi);

      Files.write(Paths.get(caminhoArquivo), resumoHex.getBytes());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}
