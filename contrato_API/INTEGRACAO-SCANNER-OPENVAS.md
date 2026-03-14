# 📘 Documentação de Integração - Scanner OpenVAS

## 🎯 Visão Geral

Esta documentação orienta o desenvolvimento de um scanner OpenVAS que se integra com a API do SentinelHub para executar scans completos em IPs de clientes Enterprise e Professional.

---

## 🔐 Autenticação

**Headers obrigatórios:**
```
X-Scanner-ID: {scanner_id}
X-API-Key: {scanner_token}
```

**Cadastro do Scanner:**
- Acesse: `https://app.sentinelhub.com.br`
- Configurações → Scan Full
- Clique em "Cadastrar Scanner Full"
- Guarde o token gerado

---

## 📡 Fluxo de Integração

```
1. GET /xml-scanner/ips-to-scan → Lista IPs para escanear
2. Para cada IP:
   a. POST /xml-scanner/start-scan → Informa início
   b. Executar scan OpenVAS
   c. A cada 5 min: POST /xml-scanner/progress → Envia progresso
   d. POST /xml-scanner/submit-xml → Envia XML com resultados
3. Loop infinito
```

---

## 🔌 Endpoints da API

### 1. GET /xml-scanner/ips-to-scan
**Descrição:** Lista IPs que precisam ser escaneados

**Headers:**
```
X-Scanner-ID: {scanner_id}
X-API-Key: {scanner_token}
```

**Response:**
```json
{
  "ips": [
    {
      "ipId": "uuid-do-ip",
      "ip": "192.168.1.1",
      "clientId": "uuid-do-cliente",
      "clientName": "Nome do Cliente",
      "plan": "ENTERPRISE",
      "lastScanned": "2026-02-18T..." ou null
    }
  ],
  "total": 25,
  "scannerId": "uuid-do-scanner"
}
```

**Frequência de scan por plano:**
- ENTERPRISE: 2x/semana (IPs que não foram escaneados há 3.5 dias)
- PROFESSIONAL: 1x/semana (IPs que não foram escaneados há 7 dias)

---

### 2. POST /xml-scanner/start-scan
**Descrição:** Informa que iniciou scan de um IP

**Headers:**
```
X-Scanner-ID: {scanner_id}
X-API-Key: {scanner_token}
Content-Type: application/json
```

**Body:**
```json
{
  "ipId": "uuid-do-ip",
  "clientId": "uuid-do-cliente"
}
```

**Response:**
```json
{
  "success": true,
  "jobId": "uuid-do-job",
  "message": "Scan iniciado"
}
```

**Importante:** Guarde o `jobId` para usar nos próximos passos.

---

### 3. POST /xml-scanner/progress
**Descrição:** Envia progresso do scan (recomendado a cada 5 minutos)

**Headers:**
```
X-Scanner-ID: {scanner_id}
X-API-Key: {scanner_token}
Content-Type: application/json
```

**Body:**
```json
{
  "jobId": "uuid-do-job",
  "progressPercent": 45
}
```

**Response:**
```json
{
  "success": true,
  "message": "Progresso atualizado"
}
```

**Valores de progresso:** 0-100

---

### 4. POST /xml-scanner/submit-xml
**Descrição:** Envia XML com resultados do scan

**Headers:**
```
X-Scanner-ID: {scanner_id}
X-API-Key: {scanner_token}
Content-Type: application/json
```

**Body:**
```json
{
  "jobId": "uuid-do-job",
  "xmlData": "<report>...</report>"
}
```

**Response:**
```json
{
  "success": true,
  "message": "XML recebido e salvo com sucesso. Processamento iniciado em background.",
  "jobId": "uuid-do-job"
}
```

**Formato do XML:** OpenVAS XML Report (formato padrão do GreenBone/OpenVAS)

---

## 💻 Exemplo de Implementação (Python)

```python
import requests
import time
import subprocess

class SentinelHubScanner:
    def __init__(self, api_url, scanner_id, scanner_token):
        self.api_url = api_url
        self.scanner_id = scanner_id
        self.scanner_token = scanner_token
        self.headers = {
            'X-Scanner-ID': scanner_id,
            'X-API-Key': scanner_token,
            'Content-Type': 'application/json'
        }
    
    def get_ips_to_scan(self):
        """Busca IPs que precisam ser escaneados"""
        url = f"{self.api_url}/xml-scanner/ips-to-scan"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def start_scan(self, ip_id, client_id):
        """Informa início do scan"""
        url = f"{self.api_url}/xml-scanner/start-scan"
        data = {
            'ipId': ip_id,
            'clientId': client_id
        }
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()['jobId']
    
    def update_progress(self, job_id, progress_percent):
        """Envia progresso do scan"""
        url = f"{self.api_url}/xml-scanner/progress"
        data = {
            'jobId': job_id,
            'progressPercent': progress_percent
        }
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
    
    def submit_xml(self, job_id, xml_data):
        """Envia XML com resultados"""
        url = f"{self.api_url}/xml-scanner/submit-xml"
        data = {
            'jobId': job_id,
            'xmlData': xml_data
        }
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def scan_ip(self, ip, target_name):
        """Executa scan OpenVAS de um IP"""
        # Criar target no OpenVAS
        # Criar task no OpenVAS
        # Iniciar scan
        # Aguardar conclusão
        # Exportar XML
        # Retornar XML
        pass
    
    def run(self):
        """Loop principal do scanner"""
        print("Scanner OpenVAS iniciado")
        
        while True:
            try:
                # 1. Buscar IPs para escanear
                data = self.get_ips_to_scan()
                ips = data['ips']
                
                if len(ips) == 0:
                    print("Nenhum IP para escanear. Aguardando...")
                    time.sleep(300)  # 5 minutos
                    continue
                
                print(f"{len(ips)} IPs para escanear")
                
                # 2. Processar cada IP
                for ip_data in ips:
                    ip = ip_data['ip']
                    ip_id = ip_data['ipId']
                    client_id = ip_data['clientId']
                    client_name = ip_data['clientName']
                    
                    print(f"Escaneando {ip} ({client_name})...")
                    
                    # 3. Iniciar scan
                    job_id = self.start_scan(ip_id, client_id)
                    print(f"Job ID: {job_id}")
                    
                    # 4. Executar scan OpenVAS
                    # (implementar integração com OpenVAS)
                    xml_data = self.scan_ip(ip, f"{client_name}-{ip}")
                    
                    # 5. Enviar progresso durante scan
                    # (chamar update_progress a cada 5 minutos)
                    
                    # 6. Enviar XML
                    self.submit_xml(job_id, xml_data)
                    print(f"XML enviado para {ip}")
                
                # Aguardar antes de buscar novos IPs
                time.sleep(3600)  # 1 hora
                
            except Exception as e:
                print(f"Erro: {e}")
                time.sleep(60)

# Uso
scanner = SentinelHubScanner(
    api_url="https://app.sentinelhub.com.br/api",
    scanner_id="seu-scanner-id",
    scanner_token="seu-token-aqui"
)
scanner.run()
```

---

## 📋 Especificações Técnicas

### Formato do XML
- **Formato:** OpenVAS XML Report (GreenBone)
- **Encoding:** UTF-8
- **Tamanho máximo:** Sem limite (testado com 300KB)

### Timeout
- **Máximo:** 6 horas
- **Comportamento:** Scans que levarem mais de 6 horas serão marcados como FAILED automaticamente

### Progresso
- **Frequência recomendada:** A cada 5 minutos
- **Valores:** 0-100 (inteiro)
- **Opcional mas recomendado** para monitoramento

### Heartbeat
- **Automático:** Atualizado ao chamar `/ips-to-scan`
- **Visível na interface:** Último heartbeat do scanner

---

## 🔍 Processamento do XML

O backend processa automaticamente o XML recebido:

**1. Extração de Dados:**
- Host IP
- Portas detectadas
- Vulnerabilidades (CVEs e findings de configuração)
- Service/Product/Version (extraído de findings de detecção)

**2. Mescla com Dados Existentes:**
- **Portas do Shodan:** Mantidas (mais completas)
- **Portas novas do OpenVAS:** Adicionadas
- **Service/Product/Version:** Aplicado apenas se porta não tiver dados do Shodan
- **CVEs:** Adicionadas (mescladas com NVD)
- **Findings:** Armazenados em tabela separada

**3. Recálculo de Risk Score:**
- Considera CVEs do NVD
- Considera CVEs do OpenVAS
- Considera findings de configuração
- Atualiza risk level do IP

---

## 📊 Monitoramento

**Interface Web:**
- Configurações → Scan Full
- Visualização em tempo real
- Scans em progresso com barra animada
- Histórico completo
- Estatísticas por scanner

**Contadores:**
- `totalScans` - Total de scans executados
- `successfulScans` - Scans concluídos
- `failedScans` - Scans que falharam ou timeout

---

## 🧪 Testes

**Script de teste fornecido:**
- `TESTAR-SCAN-FULL-VPS.sh` - Teste individual com progresso
- `TESTAR-3-XMLS-VPS.sh` - Teste de 3 XMLs sequenciais

**Executar:**
```bash
./TESTAR-3-XMLS-VPS.sh
```

**Validar:**
1. Logs do backend durante processamento
2. Interface → Configurações → Scan Full
3. Dashboard de Risco → Ver dados mesclados

---

## 🚨 Tratamento de Erros

**Erros possíveis:**

**401 - API Key inválida:**
- Token incorreto ou scanner não cadastrado
- Verificar token no banco

**403 - Scanner desativado:**
- Scanner foi desativado na interface
- Reativar ou cadastrar novo

**404 - Job não encontrado:**
- JobId inválido ao enviar XML
- Verificar se job foi criado corretamente

**500 - Erro interno:**
- Erro no processamento
- Verificar logs do backend

---

## 📞 Suporte

**Logs do backend:**
```bash
docker-compose logs backend | grep OPENVAS
```

**Verificar scanner no banco:**
```bash
docker exec -i sentinelhub-postgres psql -U sentinelhub -d sentinelhub -c "SELECT id, name, token FROM xml_scanners;"
```

**Verificar jobs:**
```bash
docker exec -i sentinelhub-postgres psql -U sentinelhub -d sentinelhub -c "SELECT id, status, progress_percent FROM xml_scan_jobs ORDER BY created_at DESC LIMIT 10;"
```

---

**Documentação de Integração - Scanner OpenVAS - SentinelHub v1.3.0**
