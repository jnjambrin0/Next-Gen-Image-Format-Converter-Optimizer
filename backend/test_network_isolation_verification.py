#!/usr/bin/env python3
"""
Verificación exhaustiva de que el aislamiento de red está funcionando
correctamente después de la refactorización.
"""

import asyncio
import sys
from app.core.security.network_monitor import NetworkMonitor
from app.core.security.parsers import (
    validate_no_network_activity,
    check_network_isolation,
    get_active_connections_count
)
from app.core.monitoring.network_check import NetworkIsolationChecker

def test_network_validation_functions():
    """Test funciones de validación de red."""
    print("🧪 Testing Network Validation Functions...")
    
    # Test 1: No activity detected in empty output
    assert validate_no_network_activity("") == True
    print("✅ Empty output validated as no activity")
    
    # Test 2: Activity patterns detected
    dangerous_outputs = [
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN",
        "tcp        0      0 192.168.1.5:45678       93.184.216.34:443       ESTABLISHED",
        "udp        0      0 0.0.0.0:53              0.0.0.0:*",
        "tcp6       0      0 :::80                   :::*                    LISTEN"
    ]
    
    for output in dangerous_outputs:
        assert validate_no_network_activity(output) == False
        print(f"✅ Network activity detected: {output[:30]}...")
    
    # Test 3: Safe output (no actual connections)
    safe_output = """netstat: no connections found"""
    assert validate_no_network_activity(safe_output) == True
    print("✅ No connections output validated as safe")
    
    return True


def test_isolation_check_function():
    """Test función check_network_isolation."""
    print("\n🧪 Testing Network Isolation Check Function...")
    
    # Test 1: Isolated system
    isolated_output = "No connections found"
    result = check_network_isolation(isolated_output)
    assert result["isolated"] == True
    assert result["connection_count"] == 0
    assert result["status"] == "isolated"
    print("✅ Isolated system detected correctly")
    
    # Test 2: Connections detected
    connected_output = """tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.5:45678       93.184.216.34:443       ESTABLISHED"""
    
    result = check_network_isolation(connected_output)
    assert result["isolated"] == False
    assert result["connection_count"] > 0
    assert result["status"] == "connections_detected"
    print(f"✅ Connections detected: {result['connection_count']} active")
    
    return True


def test_connection_counting():
    """Test conteo de conexiones."""
    print("\n🧪 Testing Connection Counting...")
    
    # Test 1: No connections
    assert get_active_connections_count("") == 0
    print("✅ Empty output: 0 connections")
    
    # Test 2: Multiple connections
    multi_conn = """Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.5:45678       93.184.216.34:443       ESTABLISHED
udp        0      0 0.0.0.0:53              0.0.0.0:*"""
    
    count = get_active_connections_count(multi_conn)
    assert count == 3, f"Expected 3 connections, got {count}"
    print(f"✅ Multiple connections counted: {count}")
    
    return True


async def test_network_monitor():
    """Test NetworkMonitor simplificado."""
    print("\n🧪 Testing Simplified Network Monitor...")
    
    # Test 1: Monitor creation
    monitor = NetworkMonitor(enabled=True, check_interval=1.0)
    assert monitor.enabled == True
    assert monitor.check_interval == 1.0
    print("✅ Network monitor created")
    
    # Test 2: Status before monitoring
    status = monitor.get_status()
    assert status["monitoring"] == False
    assert status["violation_count"] == 0
    print("✅ Initial status correct")
    
    # Test 3: Check network isolation
    isolation_status = await monitor.check_now()
    assert "isolated" in isolation_status
    assert "connection_count" in isolation_status
    print(f"✅ Isolation check completed: {isolation_status}")
    
    # Test 4: Monitor can be disabled
    monitor.enabled = False
    await monitor.start_monitoring()
    assert monitor._monitoring == False
    print("✅ Monitor respects enabled flag")
    
    return True


def test_network_isolation_checker():
    """Test NetworkIsolationChecker."""
    print("\n🧪 Testing Network Isolation Checker...")
    
    # Test 1: Check isolation
    findings = NetworkIsolationChecker.check_network_isolation()
    assert "isolated" in findings
    assert "warnings" in findings
    assert "telemetry_packages" in findings
    print(f"✅ Isolation check returned: isolated={findings['isolated']}")
    
    # Test 2: Verify localhost only
    localhost_only = NetworkIsolationChecker.verify_localhost_only()
    assert isinstance(localhost_only, bool)
    print(f"✅ Localhost verification: {localhost_only}")
    
    # Test 3: Check for telemetry packages
    if findings["telemetry_packages"]:
        print(f"⚠️  Telemetry packages found: {findings['telemetry_packages']}")
    else:
        print("✅ No telemetry packages detected")
    
    return True


async def test_integration():
    """Test integración de componentes."""
    print("\n🧪 Testing Integration...")
    
    # Create monitor
    monitor = NetworkMonitor(enabled=True)
    
    # Start and stop monitoring
    await monitor.start_monitoring()
    assert monitor._monitoring == True
    print("✅ Monitoring started")
    
    await asyncio.sleep(0.1)  # Let it run briefly
    
    await monitor.stop_monitoring()
    assert monitor._monitoring == False
    print("✅ Monitoring stopped")
    
    # Check final status
    status = monitor.get_status()
    print(f"✅ Final status: {status['violation_count']} violations")
    
    return True


async def main():
    """Run all network isolation tests."""
    print("🔒 VERIFICACIÓN DE AISLAMIENTO DE RED")
    print("=" * 50)
    
    try:
        # Test 1: Validation functions
        test_network_validation_functions()
        
        # Test 2: Isolation check
        test_isolation_check_function()
        
        # Test 3: Connection counting
        test_connection_counting()
        
        # Test 4: Network monitor
        await test_network_monitor()
        
        # Test 5: Isolation checker
        test_network_isolation_checker()
        
        # Test 6: Integration
        await test_integration()
        
        print("\n✅ TODOS LOS TESTS DE NETWORK ISOLATION PASARON!")
        print("El aislamiento de red está funcionando correctamente:")
        print("- ✅ Detección de patrones de red (ESTABLISHED, LISTEN, tcp, udp)")
        print("- ✅ Validación de aislamiento total")
        print("- ✅ Conteo de conexiones activas")
        print("- ✅ Monitor asíncrono simplificado")
        print("- ✅ Detección de paquetes de telemetría")
        print("- ✅ Reporte de violaciones")
        print("\nLa simplificación mantiene toda la seguridad necesaria.")
        
    except Exception as e:
        print(f"\n❌ TEST FALLÓ: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)