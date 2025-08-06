#!/bin/bash
# check_cli_issues.sh - Script de verificación rápida para QA

echo "============================================"
echo "Verificando problemas del CLI..."
echo "============================================"
echo ""

# 1. Check if aliases module exists
echo -n "1. Módulo aliases: "
python3 -c "from app.cli.utils import aliases; print('✓' if hasattr(aliases, 'apply_aliases') else '✗ Falta apply_aliases')" 2>/dev/null || echo "✗ Error de import"

# 2. Check plugin loader
echo -n "2. Plugin loader: "
python3 -c "from app.cli.plugins import loader; print('✓' if hasattr(loader, 'load_plugins') else '✗ Falta load_plugins')" 2>/dev/null || echo "✗ Error de import"

# 3. Check OptimizationRequest
echo -n "3. OptimizationRequest: "
cd .. && python3 -c "import sys; sys.path.insert(0, 'sdks/python'); from image_converter.models import OptimizationRequest; print('✓')" 2>/dev/null || echo "✗ No existe"
cd backend 2>/dev/null

# 4. Test basic CLI
echo -n "4. CLI básico: "
python3 img.py --help > /dev/null 2>&1 && echo "✓" || echo "✗ Error"

# 5. Test version flag
echo -n "5. Flag --version: "
python3 img.py --version > /dev/null 2>&1 && echo "✓" || echo "✗ No funciona"

# 6. Test analyze preview command
echo -n "6. Comando analyze preview: "
python3 -c "import sys; from app.cli.commands import analyze; print('✓' if hasattr(analyze, 'analyze_preview') else '✗ No existe')" 2>/dev/null || echo "✗ Error"

# 7. Test formats info command
echo -n "7. Comando formats info: "
python3 -c "import sys; from app.cli.commands import formats; print('✓' if hasattr(formats, 'formats_info') else '✗ No existe')" 2>/dev/null || echo "✗ Error"

# 8. Test presets create command
echo -n "8. Comando presets create: "
python3 -c "import sys; from app.cli.commands import presets; print('✓' if hasattr(presets, 'presets_create') else '✗ No existe')" 2>/dev/null || echo "✗ Error"

# 9. Test ErrorHandler
echo -n "9. ErrorHandler: "
python3 -c "from app.cli.utils.errors import ErrorHandler; eh = ErrorHandler(); print('✓' if hasattr(eh, 'handle') else '✗ Falta handle')" 2>/dev/null || echo "✗ Error"

# 10. Test i18n
echo -n "10. i18n set_language: "
python3 -c "from app.cli.utils import i18n; print('✓' if hasattr(i18n, 'set_language') else '✗ Falta set_language')" 2>/dev/null || echo "✗ Error"

echo ""
echo "============================================"
echo "Verificación completa!"
echo "============================================"
echo ""
echo "Para ejecutar tests completos: pytest tests/e2e/cli/ -v"
echo "Para probar un comando: python3 img.py convert file test.jpg -f webp"