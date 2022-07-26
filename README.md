# Desafio-LabSEC

Desafio final de admissão no Laboratótio de Segurança em Computação (LAbSEC - UFSC), desenvolvido no primeiro semestre de 2022.

Sistema capaz de realizar algumas operações comuns à segurança da computação.

Mais informações no arquivo ```pbad-helper-doc.pdf```, que se encontra sob o diretório ```src/main/resources/docs```

## Execução
Arquivos referentes ao processo de seleção para o projeto PBAD/LabSEC. A base
de código está em formato Maven, e portanto, a execução de

    mvn package

nesta pasta cria um pacote para distribuir o código, que estará em

    target/hiring-0.1-src.tar.bz2.

Para gerar artefatos rapidamente em uma base de código completa, execute

    mvn compile exec:java.

Para compilar o documento em LaTeX, o pacote `tikz` [1] é necessário.

[1] https://www.ctan.org/pkg/pgf
