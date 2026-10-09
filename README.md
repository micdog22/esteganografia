# Esteganografia

Esconda arquivos dentro de imagens BMP: o `esteg` grava os bytes nos bits menos significativos das cores, uma mudança invisível a olho nu. Com senha, as posições são embaralhadas e o conteúdo é cifrado com ChaCha20, autenticado com HMAC-SHA256 e protegido por PBKDF2, tudo implementado do zero em C11 para quem quer aprender como essas peças funcionam e se encaixam.

> **Aviso:** este é um projeto educacional. A criptografia (SHA-256, HMAC, PBKDF2, HKDF e ChaCha20) foi escrita do zero para estudo, passa nos vetores de teste oficiais, mas **não foi auditada**. Não use para proteger nada que realmente importe. E lembre: esteganografia LSB é detectável (veja a seção sobre esteganálise).

## Recursos

- **BMP sem compressão de 24 e 32 bits**, com cabeçalhos BITMAPINFOHEADER, V4 e V5, linhas de baixo para cima ou de cima para baixo, preenchimento de linha até múltiplos de 4 bytes e máscaras de cor (BI_BITFIELDS). Os cabeçalhos e perfis de cor da imagem original são preservados.
- **1 ou 2 bits por canal de cor**; o canal alfa nunca é tocado.
- **Cabeçalho próprio** com assinatura `EST1`, flags, nome original, tamanho e CRC-32.
- **Com senha:** chaves derivadas com PBKDF2-HMAC-SHA256 (200.000 iterações, sal aleatório de 16 bytes), posições dos bits numa permutação pseudoaleatória e conteúdo cifrado com ChaCha20 e autenticado com HMAC-SHA256 (encrypt-then-MAC, com chaves separadas).
- **Erros claros:** arquivo grande demais (com a sugestão de `--bits 2`), senha errada detectada pelo HMAC, imagem corrompida detectada pelo CRC.
- **Esteganálise embutida:** `esteg analisar` roda o ataque do qui-quadrado e mostra onde há sinais de dados escondidos.
- **Sem dependências:** só C11 e a biblioteca padrão.

## Como usar

```
esteg esconder <imagem.bmp> <arquivo> <saida.bmp> [--senha X] [--bits 1|2]
esteg revelar <imagem.bmp> [-o arquivo] [--senha X]
esteg capacidade <imagem.bmp>
esteg analisar <imagem.bmp>
```

Quanto cabe numa imagem de 640 x 480:

```
$ esteg capacidade paisagem.bmp
paisagem.bmp: 640 x 480 pixels, 24 bits por pixel, linhas de baixo para cima
canais de cor: 921.600 (3 por pixel; o alfa nunca é usado)

                              1 bit por canal   2 bits por canal
sem senha                       115.178 bytes      230.372 bytes
com senha e cifra               115.110 bytes      230.284 bytes

(já descontados os cabeçalhos; o nome do arquivo escondido também ocupa espaço)
```

Escondendo e revelando, com senha:

```
$ esteg esconder paisagem.bmp notas.zip protegida.bmp --senha "pão de queijo"
Escondi notas.zip (32.454 bytes) em protegida.bmp, usando 28,2% da capacidade com 1 bit por canal.
Com senha: posições embaralhadas, conteúdo cifrado com ChaCha20 e autenticado com HMAC-SHA256 (PBKDF2 com 200.000 iterações).

$ esteg revelar protegida.bmp --senha "pão de queijo"
Revelei notas.zip (32.454 bytes, CRC-32 0e571da0 conferido) em notas.zip.
1 bit por canal, cifrado e autenticado (HMAC-SHA256 conferido).

$ esteg revelar protegida.bmp --senha "pao de queijo"
esteg: protegida.bmp: senha incorreta ou imagem adulterada: a verificação HMAC-SHA256 falhou
```

A imagem de saída é um BMP comum, que abre em qualquer visualizador (`sips -g pixelWidth protegida.bmp` responde 640).

Outras opções:

```
--senha-stdin      lê a senha da entrada padrão (não fica no histórico do shell)
--bits 2           dobra a capacidade, mudando cada cor em até 3 níveis de 255
--sem-cifra        com senha, só embaralha as posições, sem cifrar (para comparar)
--iteracoes N      iterações do PBKDF2 (padrão 200.000)
-o arquivo         onde gravar o arquivo revelado (padrão: o nome original, sem caminho)
-f, --forcar       sobrescreve a saída se ela já existir
```

Por segurança, o nome guardado na imagem nunca é usado como caminho: `../../.bashrc` vira `.bashrc` na pasta atual, e nada é sobrescrito sem `-f`.

## Como compilar

Precisa de um compilador C11 (clang ou gcc) e `make` ou `cmake`. Testado no macOS com clang. O sal aleatório vem de `/dev/urandom`, que existe no macOS e no Linux; no Windows, use o WSL.

```sh
make                 # gera build/esteg
```

Ou com CMake:

```sh
cmake -S . -B build
cmake --build build
```

## Testes

```sh
make test            # testes de unidade e da linha de comando
make sanitize        # os mesmos testes com AddressSanitizer e UndefinedBehaviorSanitizer
ctest --test-dir build --output-on-failure   # depois do build com CMake
```

- **Criptografia:** SHA-256 (vazio, `"abc"`, a mensagem de 448 bits e um milhão de `a`), HMAC-SHA256 (RFC 4231, casos 1, 2 e 6), PBKDF2-HMAC-SHA256 (`password`/`salt` com 1 e 4096 iterações, e uma saída de 40 bytes), HKDF (RFC 5869) e o ChaCha20 (RFC 8439, função de bloco da seção 2.3.2 e cifra da 2.4.2).
- **BMP:** 24 e 32 bits, cabeçalhos de 40, 108 e 124 bytes, máscaras BGRA e RGBA, as duas ordens de linhas e larguras de 1 a 7 pixels (todos os preenchimentos), além de arquivos inválidos e formatos não suportados.
- **Ida e volta:** 144 casos (6 formatos de BMP, 1 e 2 bits por canal, 3 modos: sem senha, com senha e cifra, só com senha; e 4 tamanhos: vazio, 1 byte, aleatório e exatamente a capacidade), conferindo que só os bits menos significativos das cores mudaram (alfa, preenchimento e cabeçalhos intactos).
- **Erros:** capacidade estourada por 1 byte, senha errada (HMAC), imagem sem dados, bit trocado nos dados (CRC sem senha, HMAC com senha), assinatura e tamanho estragados.
- **Linha de comando** (`tests/cli.sh`): esconder e revelar em vários formatos, mensagens, códigos de saída, um BMP escrito pelo próprio macOS como portador e, se o `sips` existir, a confirmação de que as imagens geradas abrem no sistema.

## Como funciona

### Bits menos significativos

Num BMP de 24 bits, cada pixel tem três bytes: azul, verde e vermelho, de 0 a 255. Trocar o último bit de cada um muda a cor em no máximo 1 nível de 255, o que ninguém percebe:

```
pixel original:     azul 10110110   verde 01101001   vermelho 11001010
3 bits da mensagem:            1                0                   1
pixel com dados:    azul 10110111   verde 01101000   vermelho 11001011
```

Com `--bits 2` cada canal carrega 2 bits e muda em até 3 níveis: o dobro da capacidade, ainda difícil de ver, mas mais fácil de detectar. Os bytes da mensagem são distribuídos do bit mais significativo para o menos, um (ou dois) por canal.

### O formato BMP

```
BITMAPFILEHEADER (14 bytes)   "BM", tamanho do arquivo, deslocamento dos pixels
cabeçalho DIB (40, 108 ou 124 bytes)
    largura, altura          altura negativa = linhas de cima para baixo
    bits por pixel           24 (B G R) ou 32 (B G R A)
    compressão               0 = sem compressão, 3 = máscaras (BI_BITFIELDS)
    máscaras (V4 e V5)       onde fica cada cor dentro do pixel
pixels                       cada linha ocupa um múltiplo de 4 bytes
```

Duas armadilhas clássicas: as linhas costumam vir **de baixo para cima** (a primeira linha do arquivo é a de baixo da imagem), e cada linha é completada com zeros até um múltiplo de 4 bytes. Uma imagem de 5 pixels em 24 bits tem 15 bytes de cor e 1 de preenchimento por linha. O `esteg` percorre os canais na ordem da imagem (de cima para baixo, da esquerda para a direita), pulando o preenchimento e o alfa, então o resultado não depende de como o arquivo guarda as linhas.

### A conta da capacidade

```
canais = largura x altura x 3
bits disponíveis = (canais - área fixa) x bits por canal
capacidade = bits disponíveis / 8 - cabeçalho - nome do arquivo
```

A área fixa usa 48 canais sem senha e 208 com senha (veja o formato abaixo); o cabeçalho tem 16 bytes, ou 64 com cifra (mais as duas etiquetas do HMAC). Para 640 x 480: 921.600 canais, (921.600 - 48) / 8 - 16 = 115.178 bytes com 1 bit por canal, ou seja, cerca de um oitavo do tamanho da imagem.

### O que fica escondido

```
área fixa (sempre 1 bit por canal, nos primeiros canais)
    "EST1"        assinatura
    versão        1
    flags         senha, cifrado, 2 bits por canal
    iterações     do PBKDF2 (só com senha)
    sal           16 bytes (só com senha)

área de dados (1 ou 2 bits por canal; com senha, em ordem embaralhada)
    tamanho       8 bytes
    nome          tamanho (1 byte) e o nome, sem caminho
    CRC-32        do arquivo original
    [etiqueta]    16 bytes de HMAC sobre o cabeçalho (só cifrado)
    conteúdo
    [etiqueta]    32 bytes de HMAC sobre tudo (só cifrado)
```

A área fixa fica sempre no mesmo lugar e com 1 bit por canal: é por ela que o `esteg` descobre se há algo escondido e como ler o resto.

### Com senha: embaralhar e cifrar

```
senha + sal (16 bytes aleatórios) --PBKDF2-HMAC-SHA256, 200.000 iterações--> chave mestra
chave mestra --HKDF-Expand--> chave das posições, chave da cifra, chave do MAC
```

- **PBKDF2** repete o HMAC 200.000 vezes de propósito: testar uma senha custa caro, o que atrasa ataques de força bruta. O sal aleatório (lido de `/dev/urandom`) faz a mesma senha gerar chaves diferentes em cada imagem.
- **Três chaves independentes**, derivadas com o HKDF-Expand, porque usar a mesma chave para cifrar e autenticar é um erro clássico.
- **Posições embaralhadas:** os bits não ficam em sequência, mas numa permutação pseudoaleatória dos canais, gerada com o algoritmo de Fisher-Yates e o ChaCha20 como gerador de números. Para não precisar de um vetor com milhões de índices, o embaralhamento é "preguiçoso": um mapa guarda só as posições já trocadas.
- **ChaCha20** cifra cabeçalho, nome e conteúdo: é uma cifra de fluxo que gera bytes pseudoaleatórios a partir da chave, misturando 16 palavras de 32 bits com somas, xor e rotações por 20 rodadas.
- **HMAC-SHA256 depois de cifrar** (encrypt-then-MAC): a etiqueta é calculada sobre o texto cifrado e a área fixa. A primeira etiqueta, logo depois do cabeçalho, deixa o `esteg` recusar uma senha errada antes de confiar em qualquer tamanho decifrado; a segunda cobre tudo. As etiquetas são comparadas em tempo constante.

Sem senha não há segredo nenhum: qualquer pessoa com o `esteg` lê os dados. O CRC-32 só detecta corrupção acidental.

### Esteganálise: por que LSB é detectável

Trocar o último bit por bits aleatórios mexe no histograma de um jeito característico: o valor 6 pode virar 7 e vice-versa, mas nunca 5. Com dados aleatórios suficientes, cada par de valores (0 e 1, 2 e 3, ..., 254 e 255) fica com as duas contagens praticamente iguais. O **ataque do qui-quadrado** (Westfeld e Pfitzmann, 1999) mede exatamente isso:

```
para cada par k:  esperado = (h[2k] + h[2k+1]) / 2
qui-quadrado = soma de (h[2k] - esperado)^2 / esperado
probabilidade = P(X > qui-quadrado), com X qui-quadrado de (pares - 1) graus de liberdade
```

Perto de 1, os pares estão equalizados (sinal de dados escondidos); perto de 0, o histograma tem a "cara" de uma imagem natural. A imagem de exemplo tem 6 bits por cor (como as telas de 18 bits), então todos os seus bits menos significativos começam zerados. Escondendo os 32.454 bytes sem senha, em sequência:

```
$ esteg analisar escondida.bmp
  trecho da imagem   probabilidade
    0% a  10%       0,932  ###################
   10% a  20%       0,992  ####################
   20% a  30%       0,000
   ...
   90% a 100%       0,000
Há 2 trechos suspeitos (acima de 0,9). Imagens com muito ruído também podem dar esse sinal.
```

Os dados ocupam os primeiros 28% dos canais, e o ataque aponta exatamente os trechos cheios. Com senha, os mesmos bits ficam espalhados pela imagem inteira, nenhum trecho fica totalmente equalizado e esse ataque simples não acende. Mas isso **não** torna a imagem segura:

- Nesta imagem, 14% dos bits menos significativos passaram de 0 para 1, uma anomalia óbvia para quem olhar.
- Ataques melhores, como a análise RS (Fridrich, 2001) e a análise de pares de amostras, estimam até a quantidade de dados escondidos, mesmo espalhados; classificadores treinados vão além.
- Quem tiver a imagem original compara as duas e acha tudo. Nunca use uma foto que já foi publicada.
- Qualquer conversão (JPEG, redimensionar, a compressão de redes sociais e aplicativos de mensagem) destrói os dados escondidos.

Por isso, pense na esteganografia como uma forma de não chamar atenção, nunca como substituta da criptografia, e nesse projeto, como material de estudo.

### Mapa do código

```
include/esteg.h       API pública
src/bmp.c             leitura e escrita de BMP, ordem dos canais
src/esteg.c           formato escondido, posições embaralhadas, esconder e revelar
src/sha256.c          SHA-256, HMAC, PBKDF2 e HKDF
src/chacha20.c        ChaCha20
src/analise.c         ataque do qui-quadrado e a função gama incompleta
src/aleatorio.c       leitura de /dev/urandom (único trecho que depende do sistema)
src/main.c            o programa esteg
tests/                testes de unidade, gerador de BMPs e testes da linha de comando
```

## Limitações

- Só BMP sem compressão de 24 e 32 bits. PNG, que também é sem perdas, exigiria implementar o zlib (veja o projeto irmão [descompactador-gzip](https://github.com/micdog22/descompactador-gzip)); JPEG não serve para LSB, porque a compressão com perdas apaga os bits.
- A senha passada com `--senha` aparece na lista de processos e no histórico do shell; prefira `--senha-stdin`.
- O código não foi auditado e não tenta se defender de ataques de canal lateral (tempo de execução, consumo de memória). É material de estudo (veja o aviso no topo).

## Contribuindo

Issues e pull requests são bem-vindos.

## Licença

MIT. Veja [LICENSE](LICENSE).
