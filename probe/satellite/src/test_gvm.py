#!/usr/bin/env python3
"""
Script de teste para validar conexão com GVM.

Uso:
    python -m src.test_gvm

Requer:
    - GVM rodando (immauss/openvas)
    - Variáveis de ambiente: GVM_HOST, GVM_PORT, GVM_USERNAME, GVM_PASSWORD
"""

import os
import sys

# Adiciona src ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gvm_client import GVMClient, ScanStatus


def test_connection():
    """Testa conexão básica com GVM"""
    print("=" * 60)
    print("Teste de Conexão com GVM")
    print("=" * 60)
    
    host = os.getenv("GVM_HOST", "localhost")
    port = os.getenv("GVM_PORT", "9390")
    
    print(f"\nConectando em {host}:{port}...")
    
    try:
        with GVMClient() as gvm:
            print("✓ Conexão estabelecida!")
            print("✓ Autenticação OK!")
            
            # Listar scan configs
            print("\n--- Scan Configs Disponíveis ---")
            configs = gvm.get_scan_configs()
            for config in configs:
                print(f"  - {config.name} ({config.id[:8]}...)")
            
            # Listar scanners
            print("\n--- Scanners Disponíveis ---")
            scanners = gvm.get_scanners()
            for scanner in scanners:
                print(f"  - {scanner.name} ({scanner.id[:8]}...)")
            
            # Listar port lists
            print("\n--- Port Lists Disponíveis ---")
            port_lists = gvm.get_port_lists()
            for pl in port_lists[:5]:  # Limitar a 5
                print(f"  - {pl.name}")
            if len(port_lists) > 5:
                print(f"  ... e mais {len(port_lists) - 5}")
            
            print("\n" + "=" * 60)
            print("✓ Todos os testes passaram!")
            print("=" * 60)
            return True
            
    except Exception as e:
        print(f"\n✗ ERRO: {e}")
        print("\nVerifique:")
        print("  1. OpenVAS está rodando?")
        print("  2. Porta 9390 está acessível?")
        print("  3. Credenciais estão corretas?")
        return False


def test_scan_workflow():
    """Testa workflow completo de scan (sem executar de verdade)"""
    print("\n" + "=" * 60)
    print("Teste de Workflow de Scan (dry-run)")
    print("=" * 60)
    
    try:
        with GVMClient() as gvm:
            # Criar port list de teste
            print("\n1. Criando port list de teste...")
            port_list_id = gvm.create_port_list(
                name="test-portlist-delete-me",
                ports=[22, 80, 443]
            )
            print(f"   ✓ Port list criada: {port_list_id[:8]}...")
            
            # Criar target de teste
            print("\n2. Criando target de teste...")
            target_id = gvm.create_target(
                name="test-target-delete-me",
                hosts="127.0.0.1",
                port_list_id=port_list_id
            )
            print(f"   ✓ Target criado: {target_id[:8]}...")
            
            # Criar task de teste
            print("\n3. Criando task de teste...")
            task_id = gvm.create_task(
                name="test-task-delete-me",
                target_id=target_id
            )
            print(f"   ✓ Task criada: {task_id[:8]}...")
            
            # Verificar status
            print("\n4. Verificando status...")
            status, progress = gvm.get_task_status(task_id)
            print(f"   ✓ Status: {status.value}, Progress: {progress}%")
            
            # Limpar recursos
            print("\n5. Limpando recursos de teste...")
            gvm.delete_task(task_id)
            print("   ✓ Task removida")
            gvm.delete_target(target_id)
            print("   ✓ Target removido")
            gvm.delete_port_list(port_list_id)
            print("   ✓ Port list removida")
            
            print("\n" + "=" * 60)
            print("✓ Workflow de scan validado com sucesso!")
            print("=" * 60)
            return True
            
    except Exception as e:
        print(f"\n✗ ERRO no workflow: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("   GREENBONE GVM INTEGRATION TEST")
    print("=" * 60)
    
    # Config
    print(f"\nConfiguração:")
    print(f"  GVM_HOST: {os.getenv('GVM_HOST', 'localhost')}")
    print(f"  GVM_PORT: {os.getenv('GVM_PORT', '9390')}")
    print(f"  GVM_USERNAME: {os.getenv('GVM_USERNAME', 'admin')}")
    print(f"  GVM_PASSWORD: {'*' * len(os.getenv('GVM_PASSWORD', 'admin'))}")
    
    # Teste 1: Conexão
    if not test_connection():
        sys.exit(1)
    
    # Teste 2: Workflow (opcional)
    response = input("\nDeseja testar o workflow completo? (s/N): ")
    if response.lower() == 's':
        if not test_scan_workflow():
            sys.exit(1)
    
    print("\n✓ Todos os testes completados com sucesso!")


if __name__ == "__main__":
    main()
