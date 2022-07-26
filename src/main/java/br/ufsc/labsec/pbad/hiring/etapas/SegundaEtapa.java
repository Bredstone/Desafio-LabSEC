package br.ufsc.labsec.pbad.hiring.etapas;

import java.security.KeyPair;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.EscritorDeChaves;

/**
 * <b>Segunda etapa - gerar chaves assimétricas</b>
 * <p>
 * A partir dessa etapa, tudo que será feito envolve criptografia assimétrica.
 * A tarefa aqui é parecida com a etapa anterior, pois refere-se apenas a
 * criar e armazenar chaves, mas nesse caso será usado um algoritmo de
 * criptografia assimétrica, o ECDSA.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um par de chaves usando o algoritmo ECDSA com o tamanho de 256 bits;
 * </li>
 * <li>
 * gerar outro par de chaves, mas com o tamanho de 521 bits. Note que esse
 * par de chaves será para a AC-Raiz;
 * </li>
 * <li>
 * armazenar em disco os pares de chaves em formato PEM.
 * </li>
 * </ul>
 */
public class SegundaEtapa {

  public static void executarEtapa() {
    GeradorDeChaves gerador = new GeradorDeChaves(Constantes.algoritmoChave);
    KeyPair parUsuario = gerador.gerarParDeChaves(256);
    KeyPair parAcRaiz = gerador.gerarParDeChaves(521);

    EscritorDeChaves.escreveChaveEmDisco(parUsuario.getPrivate(), Constantes.caminhoChavePrivadaUsuario);
    EscritorDeChaves.escreveChaveEmDisco(parUsuario.getPublic(), Constantes.caminhoChavePublicaUsuario);
    EscritorDeChaves.escreveChaveEmDisco(parAcRaiz.getPrivate(), Constantes.caminhoChavePrivadaAc);
    EscritorDeChaves.escreveChaveEmDisco(parAcRaiz.getPublic(), Constantes.caminhoChavePublicaAc);
  }

}
