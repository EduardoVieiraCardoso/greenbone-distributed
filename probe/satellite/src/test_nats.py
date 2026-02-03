#!/usr/bin/env python3
"""
Script de teste para validar conexão com NATS.

Uso:
    python -m src.test_nats

Requer:
    - NATS server rodando
    - Variáveis: NATS_URL, NATS_TOKEN, PROBE_ID
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.nats_client import NATSManager, ScanJob


async def test_connection():
    """Testa conexão básica com NATS"""
    print("=" * 60)
    print("Teste de Conexão com NATS")
    print("=" * 60)
    
    nats_url = os.getenv("NATS_URL", "nats://localhost:4222")
    probe_id = os.getenv("PROBE_ID", "test-probe")
    
    print(f"\nConectando em {nats_url}...")
    print(f"Probe ID: {probe_id}")
    
    nats = NATSManager(
        probe_id=probe_id,
        probe_location="Test Location"
    )
    
    try:
        await nats.connect()
        print("✓ Conexão estabelecida!")
        
        # Tentar registrar
        print("\nRegistrando probe...")
        registered = await nats.register()
        if registered:
            print("✓ Registro aceito pelo orchestrator!")
        else:
            print("⚠ Registro não confirmado (orchestrator pode não estar rodando)")
        
        # Subscrever a jobs
        print("\nSubscrevendo a jobs...")
        job_received = asyncio.Event()
        received_job = None
        
        async def job_handler(job: ScanJob):
            nonlocal received_job
            received_job = job
            job_received.set()
        
        await nats.subscribe_jobs(job_handler)
        print(f"✓ Subscrito em: probes.{probe_id}.jobs")
        
        # Aguardar job por 5 segundos
        print("\nAguardando job por 5 segundos...")
        print("(Envie um job para testar ou pressione Ctrl+C)")
        
        try:
            await asyncio.wait_for(job_received.wait(), timeout=5)
            print(f"✓ Job recebido: {received_job.job_id}")
        except asyncio.TimeoutError:
            print("⚠ Nenhum job recebido (timeout)")
        
        await nats.disconnect()
        print("\n✓ Desconectado com sucesso!")
        
        print("\n" + "=" * 60)
        print("✓ Teste de conexão NATS completado!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n✗ ERRO: {e}")
        print("\nVerifique:")
        print("  1. NATS server está rodando?")
        print("  2. URL está correta?")
        print("  3. Token está correto?")
        return False


async def test_publish():
    """Testa publicação de mensagens"""
    print("\n" + "=" * 60)
    print("Teste de Publicação NATS")
    print("=" * 60)
    
    from src.nats_client import ScanResult
    from datetime import datetime
    
    probe_id = os.getenv("PROBE_ID", "test-probe")
    
    nats = NATSManager(
        probe_id=probe_id,
        probe_location="Test Location"
    )
    
    try:
        await nats.connect()
        
        # Publicar resultado fake
        result = ScanResult(
            job_id="test-job-123",
            probe_id=probe_id,
            status="completed",
            completed_at=datetime.utcnow().isoformat(),
            summary={
                "hosts_scanned": 1,
                "vulns_high": 0,
                "vulns_medium": 2,
                "vulns_low": 5
            }
        )
        
        print("\nPublicando resultado de teste...")
        await nats.publish_result(result)
        print("✓ Resultado publicado!")
        
        await nats.disconnect()
        return True
        
    except Exception as e:
        print(f"\n✗ ERRO: {e}")
        return False


async def main():
    print("\n" + "=" * 60)
    print("   NATS CONNECTION TEST")
    print("=" * 60)
    
    print(f"\nConfiguração:")
    print(f"  NATS_URL: {os.getenv('NATS_URL', 'nats://localhost:4222')}")
    print(f"  PROBE_ID: {os.getenv('PROBE_ID', 'test-probe')}")
    print(f"  NATS_TOKEN: {'*' * 8 if os.getenv('NATS_TOKEN') else '(não definido)'}")
    
    if not await test_connection():
        sys.exit(1)
    
    response = input("\nDeseja testar publicação? (s/N): ")
    if response.lower() == 's':
        if not await test_publish():
            sys.exit(1)
    
    print("\n✓ Todos os testes NATS completados!")


if __name__ == "__main__":
    asyncio.run(main())
