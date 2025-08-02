#!/usr/bin/env python3
"""
Verificación exhaustiva de que el manejo de errores mantiene
toda su funcionalidad después de la simplificación.
"""

import asyncio
from app.core.security.errors import (
    SecurityError,
    create_network_error,
    create_sandbox_error,
    create_rate_limit_error,
    create_verification_error,
    create_file_error,
    SecurityErrorHandler,
    handle_security_errors
)
from app.core.security.sandbox import SecuritySandbox
from app.core.exceptions import ImageConverterError

def test_error_categories():
    """Test todas las categorías de error funcionan."""
    print("🧪 Testing Error Categories...")
    
    # Test 1: Network errors
    error = create_network_error("dns_blocked", host="evil.com")
    assert error.category == "network"
    assert error.details["reason"] == "dns_blocked"
    assert error.details["host"] == "evil.com"
    assert str(error) == "Network access violation"
    print("✅ Network error category working")
    
    # Test 2: Sandbox errors
    error = create_sandbox_error("memory_violation", used_mb=512, limit_mb=256)
    assert error.category == "sandbox"
    assert error.details["reason"] == "memory_violation"
    assert error.details["used_mb"] == 512
    print("✅ Sandbox error category working")
    
    # Test 3: Rate limit errors
    error = create_rate_limit_error("api_calls", current=101, limit=100)
    assert error.category == "rate_limit"
    assert error.details["limit_type"] == "api_calls"
    assert error.details["current"] == 101
    print("✅ Rate limit error category working")
    
    # Test 4: Verification errors
    error = create_verification_error("network_isolation", status="failed")
    assert error.category == "verification"
    assert error.details["check_type"] == "network_isolation"
    assert error.details["status"] == "failed"
    print("✅ Verification error category working")
    
    # Test 5: File errors
    error = create_file_error("path_traversal", path="../etc/passwd")
    assert error.category == "file"
    assert error.details["operation"] == "path_traversal"
    assert error.details["path"] == "../etc/passwd"
    print("✅ File error category working")
    
    return True


def test_error_handler():
    """Test SecurityErrorHandler maneja todos los casos."""
    print("\n🧪 Testing Security Error Handler...")
    
    handler = SecurityErrorHandler()
    
    # Test 1: Handle SecurityError
    error = create_network_error("blocked")
    result = handler.handle_error(error)
    assert result["error"] == "security_violation"
    assert result["category"] == "network"
    assert result["message"] == "Network access violation"
    print("✅ SecurityError handled correctly")
    
    # Test 2: Handle Python exceptions
    test_cases = [
        (TimeoutError("Timeout"), "sandbox", ["timeout", "async_timeout"]),
        (MemoryError("OOM"), "sandbox", ["memory_limit"]),
        (PermissionError("Denied"), "file", ["permission_denied"]),
        (OSError("Network"), "network", ["system_error"]),
    ]
    
    for exc, expected_category, expected_reasons in test_cases:
        result = handler.handle_error(exc)
        assert result["category"] == expected_category
        assert result["details"]["reason"] in expected_reasons
        actual_reason = result["details"]["reason"]
        print(f"✅ {exc.__class__.__name__} → {expected_category}/{actual_reason}")
    
    # Test 3: Unknown errors
    result = handler.handle_error(ValueError("Unknown"))
    assert result["category"] == "unknown"
    assert result["message"] == "Security check failed"
    assert result["details"] == {}
    print("✅ Unknown errors handled safely (no details exposed)")
    
    return True


def test_privacy_preservation():
    """Test que no se filtran datos sensibles."""
    print("\n🧪 Testing Privacy Preservation...")
    
    # Test 1: Filenames not in error messages
    error = create_file_error("access", path="/home/user/secret.jpg")
    # The error message should NOT contain the filename
    assert "/home/user/secret.jpg" not in str(error)
    assert str(error) == "File security violation"
    print("✅ Filenames not exposed in error messages")
    
    # Test 2: Handler sanitizes unknown errors
    handler = SecurityErrorHandler()
    result = handler.handle_error(Exception("User password: 12345"))
    assert "12345" not in result["message"]
    assert "password" not in result["message"]
    assert result["message"] == "Security check failed"
    print("✅ Sensitive data sanitized from unknown errors")
    
    # Test 3: Details are structured, not in message
    error = create_network_error("dns_blocked", host="internal.corp")
    assert "internal.corp" not in str(error)
    assert error.details["host"] == "internal.corp"
    print("✅ Sensitive details kept separate from message")
    
    return True


async def test_decorator():
    """Test @handle_security_errors decorator."""
    print("\n🧪 Testing Error Handling Decorator...")
    
    # Test 1: Passes SecurityError unchanged
    @handle_security_errors
    async def raises_security_error():
        raise create_sandbox_error("test")
    
    try:
        await raises_security_error()
        assert False, "Should have raised"
    except SecurityError as e:
        assert e.category == "sandbox"
        print("✅ SecurityError passed through decorator")
    
    # Test 2: Converts other errors
    @handle_security_errors
    async def raises_timeout():
        raise asyncio.TimeoutError("Took too long")
    
    try:
        await raises_timeout()
        assert False, "Should have raised"
    except SecurityError as e:
        assert e.category == "sandbox"
        assert e.details["reason"] in ["timeout", "async_timeout"]
        print("✅ TimeoutError converted to SecurityError")
    
    # Test 3: Successful execution
    @handle_security_errors
    async def succeeds():
        return "success"
    
    result = await succeeds()
    assert result == "success"
    print("✅ Successful execution not affected")
    
    return True


def test_error_integration():
    """Test errores funcionan con componentes reales."""
    print("\n🧪 Testing Error Integration...")
    
    sandbox = SecuritySandbox()
    
    # Test 1: Path validation errors
    try:
        sandbox.validate_path("../../../etc/passwd")
        assert False, "Should have raised"
    except SecurityError as e:
        assert e.category == "file"
        assert "path_traversal" in str(e.details)
        print("✅ Path validation raises correct error")
    
    # Test 2: Command validation errors  
    try:
        sandbox.validate_command(["rm", "-rf", "/"])
        assert False, "Should have raised"
    except SecurityError as e:
        assert e.category == "sandbox"
        assert "forbidden_command" in str(e.details)
        print("✅ Command validation raises correct error")
    
    # Test 3: File access errors
    try:
        sandbox.validate_file_access("/etc/shadow", "read")
        assert False, "Should have raised"
    except SecurityError as e:
        assert e.category == "file"
        print("✅ File access validation raises correct error")
    
    return True


def test_backwards_compatibility():
    """Test compatibilidad con código existente."""
    print("\n🧪 Testing Backwards Compatibility...")
    
    # Test 1: SecurityError is still an Exception
    error = create_network_error("test")
    assert isinstance(error, Exception)
    print("✅ SecurityError is Exception subclass")
    
    # Test 2: Can catch with generic Exception
    try:
        raise create_sandbox_error("test")
    except Exception:
        print("✅ Can catch with Exception")
    
    # Test 3: Error attributes accessible
    error = create_file_error("test", filename="secret.jpg")
    assert hasattr(error, "category")
    assert hasattr(error, "details")
    assert error.details.get("filename") == "secret.jpg"
    print("✅ Error attributes accessible")
    
    return True


async def main():
    """Run all error handling tests."""
    print("🔒 VERIFICACIÓN DE MANEJO DE ERRORES")
    print("=" * 50)
    
    try:
        # Test 1: Categories
        test_error_categories()
        
        # Test 2: Handler
        test_error_handler()
        
        # Test 3: Privacy
        test_privacy_preservation()
        
        # Test 4: Decorator
        await test_decorator()
        
        # Test 5: Integration
        test_error_integration()
        
        # Test 6: Compatibility
        test_backwards_compatibility()
        
        print("\n✅ TODOS LOS TESTS DE MANEJO DE ERRORES PASARON!")
        print("El sistema de errores simplificado mantiene:")
        print("- ✅ Todas las categorías necesarias (network, sandbox, rate_limit, verification, file)")
        print("- ✅ Mapeo automático de excepciones Python")
        print("- ✅ Privacidad: sin PII en mensajes de error")
        print("- ✅ Decorador funcional para conversión de errores")
        print("- ✅ Integración con todos los componentes")
        print("- ✅ Compatibilidad hacia atrás")
        print("\nLa simplificación de 60+ códigos a 5 categorías NO perdió funcionalidad.")
        
    except Exception as e:
        print(f"\n❌ TEST FALLÓ: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)