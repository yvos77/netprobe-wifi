# NetProbe Wi-Fi

Ferramenta de inventário para redes domésticas. Descobre os dispositivos ativos de uma faixa de IPs, encontra também os que bloqueiam ping (via ARP), monta a tabela IP ↔ MAC, lista as portas TCP abertas e mostra o status de cada dispositivo em tempo real numa interface web.

Trabalho final da disciplina de Redes de Computadores — IESB.
Grupo: Yuri Victor, Danielly Luz, Felipe Oliveira, Gabriel Vieira, Guilherme Ferreira, Heitor Ribeiro e Pedro Arthur.

## Funcionalidades

| Recurso | Como funciona |
|---|---|
| **Ping Sweep** | Envia ICMP Echo Request para todos os IPs da faixa em paralelo, com timeout configurável |
| **ARP Probe** | Envia ARP Request para os IPs que não responderam ao ping e identifica quem existe, mas bloqueia ICMP |
| **Tabela IP/MAC** | Associa cada IP ao MAC da resposta ARP e alerta quando dois MACs respondem pelo mesmo IP (conflito) |
| **Portas abertas** | TCP connect scan nos hosts online, na faixa de portas escolhida |
| **Tempo real** | Repete a varredura a cada N segundos; aparelhos que saem viram *Offline* e os que voltam, *Online* |

## Requisitos

- Python 3.10 ou superior
- Privilégios de **root (Linux/macOS)** ou **administrador (Windows)** — o ARP Probe monta quadros Ethernet diretamente na placa de rede
- Windows: [Npcap](https://npcap.com/#download) instalado (opção *WinPcap API-compatible Mode*)

Sem privilégios a ferramenta continua funcionando, mas usa o cache ARP do sistema e não detecta conflitos de IP. O modo em uso aparece na tela, abaixo da barra de progresso.

## Instalação

### Linux

```bash
git clone https://github.com/yvos77/netprobe-wifi.git
cd netprobe-wifi
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo .venv/bin/python app.py --no-browser
```

Abra **http://127.0.0.1:5000** no navegador.

### Windows

```powershell
git clone https://github.com/yvos77/netprobe-wifi.git
cd netprobe-wifi
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Execute o último comando num terminal aberto **como administrador**. O navegador abre sozinho.

## Uso

1. Confira a **rede (CIDR)** — vem preenchida com a /24 da sua placa de rede.
2. Ajuste os timeouts e a faixa de portas, se quiser.
3. Clique em **Iniciar varredura**. Com *Repetir a cada 10 segundos* marcado (padrão), a ferramenta fica monitorando até você clicar em **Parar**.

## Estrutura

```
app.py                 servidor Flask e API REST
scanner/
  network.py           detecção da rede local e validação do CIDR
  icmp.py              ping sweep
  arp.py               ARP probe (Scapy) e leitura do cache ARP
  inventory.py         tabela IP/MAC e status dos dispositivos
  ports.py             varredura de portas TCP
  engine.py            ciclo de varredura, monitoramento e cancelamento
templates/index.html   página da interface
static/                estilos e JavaScript da interface
```

## API

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/status` | Fase atual, progresso, resumo e lista de dispositivos |
| `POST` | `/api/scan` | Inicia a varredura com os parâmetros enviados em JSON |
| `POST` | `/api/stop` | Interrompe a varredura em andamento |

> Use apenas em redes suas ou com autorização.
