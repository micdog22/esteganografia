#!/bin/sh
# Testes da linha de comando do esteg.
# Uso: sh tests/cli.sh <caminho do esteg> <caminho do gerar_bmp>
set -u
ESTEG=$1
GERAR=$2
case $ESTEG in /*) ;; *) ESTEG=$(pwd)/$ESTEG ;; esac
case $GERAR in /*) ;; *) GERAR=$(pwd)/$GERAR ;; esac

TMP=$(mktemp -d "${TMPDIR:-/tmp}/esteg-teste.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT INT TERM
cd "$TMP" || exit 1

pass=0
fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "  FALHOU: $*"; }

"$GERAR" 160 120 24 paisagem.bmp --paisagem
"$GERAR" 151 97 32 rgba.bmp --v5 --rgba --topo --semente 5
"$GERAR" 140 100 32 v4.bmp --v4 --semente 9
# Arquivo "secreto" determinístico com bytes de todo tipo.
"$GERAR" 40 30 24 segredo.bin --semente 3
cp segredo.bin "relatório 2026.dat"

# 1. Sem senha, 1 bit, BMP de 24 bits de baixo para cima.
if "$ESTEG" esconder paisagem.bmp segredo.bin saida1.bmp > log.txt; then ok; else bad "esconder sem senha"; fi
if grep -q "Escondi segredo.bin" log.txt; then ok; else bad "mensagem de esconder: $(cat log.txt)"; fi
if "$ESTEG" revelar saida1.bmp -o volta1.bin > log.txt && cmp -s segredo.bin volta1.bin; then ok; else bad "revelar sem senha"; fi
if grep -q "CRC-32 .* conferido" log.txt; then ok; else bad "mensagem de revelar: $(cat log.txt)"; fi

# 2. Com senha, 2 bits, 32 bits RGBA de cima para baixo (V5).
"$ESTEG" esconder rgba.bmp "relatório 2026.dat" saida2.bmp --senha "pão de queijo" --bits 2 --iteracoes 5000 > /dev/null
if [ $? -eq 0 ]; then ok; else bad "esconder com senha"; fi
mkdir revelado
(cd revelado && "$ESTEG" revelar ../saida2.bmp --senha "pão de queijo" > ../log.txt)
if cmp -s segredo.bin "revelado/relatório 2026.dat"; then ok; else bad "revelar com o nome original"; fi
if grep -q "cifrado e autenticado" log.txt; then ok; else bad "mensagem com senha: $(cat log.txt)"; fi

# 3. Senha pela entrada padrão, BMP V4 de 32 bits.
printf 'senha secreta\n' | "$ESTEG" esconder v4.bmp segredo.bin saida3.bmp --senha-stdin --iteracoes 2000 > /dev/null
printf 'senha secreta\n' | "$ESTEG" revelar saida3.bmp --senha-stdin -o volta3.bin > /dev/null
if cmp -s segredo.bin volta3.bin; then ok; else bad "--senha-stdin"; fi

# 4. Erros: senha errada, sem senha, capacidade, imagem sem dados, sobrescrever.
msg=$("$ESTEG" revelar saida2.bmp --senha "pao de queijo" -o x.bin 2>&1)
if [ $? -eq 1 ] && echo "$msg" | grep -q "HMAC-SHA256 falhou"; then ok; else bad "senha errada: $msg"; fi
msg=$("$ESTEG" revelar saida2.bmp -o x.bin 2>&1)
if [ $? -eq 1 ] && echo "$msg" | grep -q "protegida com senha"; then ok; else bad "sem senha: $msg"; fi
if [ ! -e x.bin ]; then ok; else bad "não devia criar arquivo em caso de erro"; fi
"$GERAR" 300 300 24 grande.bin --semente 4
msg=$("$ESTEG" esconder paisagem.bmp grande.bin cheio.bmp 2>&1)
if [ $? -eq 1 ] && echo "$msg" | grep -q "não cabe" && echo "$msg" | grep -q "com --bits 2"; then ok; else bad "capacidade: $msg"; fi
if [ ! -e cheio.bmp ]; then ok; else bad "não devia gravar a saída sem espaço"; fi
msg=$("$ESTEG" revelar paisagem.bmp 2>&1)
if [ $? -eq 1 ] && echo "$msg" | grep -q "assinatura EST1 ausente"; then ok; else bad "imagem limpa: $msg"; fi
msg=$("$ESTEG" esconder paisagem.bmp segredo.bin saida1.bmp 2>&1)
if [ $? -eq 1 ] && echo "$msg" | grep -q "já existe"; then ok; else bad "sobrescrever sem -f: $msg"; fi
if "$ESTEG" esconder paisagem.bmp segredo.bin saida1.bmp -f > /dev/null; then ok; else bad "sobrescrever com -f"; fi
msg=$("$ESTEG" revelar saida1.bmp -o volta1.bin 2>&1)
if [ $? -eq 1 ] && echo "$msg" | grep -q "já existe"; then ok; else bad "revelar sem -f: $msg"; fi
printf 'nao sou bmp' > texto.bmp
msg=$("$ESTEG" capacidade texto.bmp 2>&1)
if [ $? -eq 1 ] && echo "$msg" | grep -q "não é um arquivo BMP"; then ok; else bad "não BMP: $msg"; fi
"$ESTEG" esconder paisagem.bmp segredo.bin saida9.bmp --bits 3 > /dev/null 2>&1
if [ $? -eq 2 ]; then ok; else bad "--bits 3 devia dar erro de uso"; fi

# 5. Capacidade e análise.
out=$("$ESTEG" capacidade paisagem.bmp)
if echo "$out" | grep -q "160 x 120 pixels, 24 bits por pixel, linhas de baixo para cima" &&
   echo "$out" | grep -q "57.600"; then ok; else bad "capacidade: $out"; fi
out=$("$ESTEG" capacidade rgba.bmp)
if echo "$out" | grep -q "de cima para baixo"; then ok; else bad "ordem das linhas: $out"; fi
out=$("$ESTEG" analisar paisagem.bmp)
if echo "$out" | grep -q "Nenhum trecho suspeito"; then ok; else bad "analisar limpa: $out"; fi
# 5000 bytes ocupam cerca de 70% dos canais, em ordem: os primeiros trechos acendem.
head -c 5000 grande.bin > meio.bin
"$ESTEG" esconder paisagem.bmp meio.bin cheia.bmp > /dev/null
out=$("$ESTEG" analisar cheia.bmp)
if echo "$out" | grep -q "suspeito"; then ok; else bad "analisar com dados: $out"; fi

# 6. O BMP gerado continua sendo um BMP válido para o sistema (sips, no macOS),
#    e um BMP escrito pelo próprio sistema também serve de portador.
if command -v sips > /dev/null 2>&1; then
    if sips -s format bmp paisagem.bmp --out do_sistema.bmp > /dev/null 2>&1 &&
       "$ESTEG" esconder do_sistema.bmp segredo.bin saida4.bmp --senha x --iteracoes 1000 > /dev/null &&
       "$ESTEG" revelar saida4.bmp --senha x -o volta4.bin > /dev/null && cmp -s segredo.bin volta4.bin; then
        ok
    else
        bad "ida e volta num BMP escrito pelo sips"
    fi
    for f in saida1.bmp saida2.bmp saida3.bmp saida4.bmp; do
        w=$(sips -g pixelWidth "$f" 2>/dev/null | awk '/pixelWidth/ {print $2}')
        case $f in
            saida1.bmp) want=160 ;;
            saida2.bmp) want=151 ;;
            saida4.bmp) want=160 ;;
            *) want=140 ;;
        esac
        if [ "$w" = "$want" ]; then ok; else bad "sips -g pixelWidth $f deu '$w'"; fi
    done
fi

if "$ESTEG" --help | grep -q "esteg esconder"; then ok; else bad "--help"; fi

echo "$pass verificações da linha de comando, $fail falhas"
[ "$fail" -eq 0 ]
