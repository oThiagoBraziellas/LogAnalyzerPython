# LogAnalyzer em Python

Analisador de logs de acesso no estilo nginx, escrito em Python puro. Lê arquivos ou a entrada padrão linha a linha (streaming), sem carregar o log inteiro na memória, e produz contagem de códigos de status, caminhos mais acessados, IPs mais frequentes, volume transferido e percentis de latência (p50, p95, p99), em texto ou JSON.

## Por que este projeto

Ler logs para responder "o que quebrou e quando?" é rotina de SRE e de qualquer engenheiro de backend em produção, e perguntas de entrevista sobre processamento de arquivos grandes, percentis e agregação em uma passada aparecem com frequência em empresas como Google, Amazon e Meta. O projeto junta três tópicos que valem a pena dominar: parsing robusto de dados sujos, agregação em fluxo com memória controlada e a diferença entre média e cauda de latência (p95), que é o que o usuário realmente sente.

## Recursos

- Parser para o formato `combined` do nginx, com tempo de requisição opcional no final (`$request_time`, com ou sem aspas). O formato comum (common log format) também funciona.
- Tratamento de campos com `-`, aspas escapadas, fuso horário no timestamp e requisições malformadas (sondas binárias são contadas, não derrubam a análise).
- Linhas inválidas são contadas em `malformed` e ignoradas.
- Relatório: total, período, bytes, taxa de erro (4xx + 5xx), contagem por status e por classe, top caminhos, top IPs, latência (mín, p50, p95, p99, máx, média) e os caminhos mais lentos por p95.
- Saída em texto ou `--json`.
- Entrada por arquivo(s), `-` ou stdin, o que permite `zcat access.log.gz | python3 -m log_analyzer`.
- Amostragem por reservatório quando o número de medições de latência passa do limite, mantendo a memória constante.

## Como executar

Requer Python 3.8 ou superior. Dentro da pasta do projeto, usando o log de exemplo (2000 linhas, produzido de forma determinística por `samples/make_sample.py`):

```bash
python3 -m log_analyzer samples/access.sample
python3 -m log_analyzer samples/access.sample --top 5 --json
cat samples/access.sample | python3 -m log_analyzer -
```

Para analisar um log real, o formato esperado é o `combined` com `$request_time` ao final:

```nginx
log_format timed '$remote_addr - $remote_user [$time_local] "$request" '
                 '$status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time';
```

Para recriar o exemplo: `python3 samples/make_sample.py > samples/access.sample`.

## Como testar

```bash
python3 -m unittest -v
```

Os testes cobrem o parser (formato completo, comum, `-`, aspas escapadas, fusos, lixo), o cálculo de percentil por posição mais próxima, as agregações, empates na ordenação, o reservatório de amostras, a serialização JSON e a CLI (arquivo, stdin, arquivo inexistente e o log de exemplo).

## Decisões de projeto

- **Uma passada, linha a linha.** O arquivo é iterado de forma preguiçosa; contadores crescem com o número de valores distintos (caminhos, IPs), não com o número de linhas. Tempo O(n); o custo final de ordenar é O(k log k) sobre os valores distintos e as amostras.
- **Query string removida do caminho.** `/api/items?page=2` e `?page=3` contam como o mesmo recurso. Sem isso, o top de caminhos seria dominado por variações.
- **Percentil por posição mais próxima (nearest rank).** É simples, sempre devolve um valor realmente observado e é determinístico. Interpolação daria números "mais suaves", mas não observados.
- **Reservatório (algoritmo R) acima de 100 mil amostras.** Percentis exatos exigem guardar todos os valores; o reservatório troca exatidão por memória constante. Abaixo do limite o resultado é exato. A semente é fixa por padrão, para resultados reproduzíveis.
- **Latência por caminho limitada.** No máximo 5000 caminhos e 1000 amostras por caminho; caminhos com menos de 5 medições não entram no ranking de lentos, para não destacar acasos.
- **Ordenação determinística.** Empates são desfeitos por nome, o que torna a saída estável e testável.
- **Trade-off:** expressão regular única, fácil de ler e de estender, mais lenta que um parser manual por posição. Para dezenas de milhões de linhas, um parser com `str.split` e aspas controladas seria mais rápido.

## Estrutura de pastas

```
LogAnalyzer/
├── log_analyzer/
│   ├── __init__.py
│   ├── __main__.py
│   ├── parser.py        # linha -> LogEntry
│   ├── analyzer.py      # agregação em fluxo e percentis
│   └── cli.py           # argparse, formatação do relatório
├── samples/
│   ├── make_sample.py
│   └── access.sample
├── tests/
│   ├── test_parser.py
│   ├── test_analyzer.py
│   └── test_cli.py
├── LICENSE
└── README.md
```

## Limitações conhecidas

- Formato de log fixo (combined + tempo opcional); logs em JSON ou com campos personalizados não são suportados.
- Sem filtros por intervalo de tempo ou por status, e sem janelas deslizantes (por minuto).
- Os percentis ficam aproximados quando há mais amostras do que o reservatório comporta.
- Linhas com mais de um fuso horário misturados são aceitas, mas o período é comparado por instante absoluto.
- Não há leitura direta de arquivos `.gz`; use `zcat` e um pipe.

## Licença

MIT. Veja o arquivo [LICENSE](LICENSE).
