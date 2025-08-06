# CLI Visual Features E2E Tests

Este directorio contiene tests end-to-end ultra realistas para probar todas las funcionalidades visuales del CLI implementadas en Story 6.2.

## 📋 Requisitos Previos

1. **Backend corriendo**:
   ```bash
   cd backend
   uvicorn app.main:app --reload --port 8080
   ```

2. **CLI instalado**:
   ```bash
   cd backend
   pip install -e .
   ```

3. **Dependencias de test**:
   ```bash
   pip install pytest pytest-mock requests pillow
   ```

## 🧪 Tests Disponibles

### 1. **Test E2E Principal** (`test_cli_visual_e2e.py`)
Prueba todas las funcionalidades visuales:
- ✅ Salida con temas y colores
- ✅ Soporte de emojis con fallback
- ✅ Barras de progreso animadas
- ✅ Tablas inteligentes
- ✅ Preview ASCII/ANSI
- ✅ Modo TUI
- ✅ Detección de capacidades del terminal
- ✅ Manejo de errores con estilo

**Ejecución**:
```bash
# Con salida visible (recomendado para ver los colores)
pytest test_cli_visual_e2e.py -v --capture=no

# Solo tests específicos
pytest test_cli_visual_e2e.py::TestCLIVisualFeatures::test_convert_with_themed_output -v
```

### 2. **Test de Seguridad** (`test_cli_security.py`)
Prueba las nuevas características de seguridad:
- 🛡️ PathSanitizer - Prevención de path traversal
- 🛡️ RateLimiter - Control de tasa de actualizaciones
- 🛡️ Límites de tamaño de archivo
- 🛡️ Sanitización de nombres
- 🛡️ Chequeos de permisos

**Ejecución**:
```bash
pytest test_cli_security.py -v

# Test específico de seguridad
pytest test_cli_security.py::TestPathSanitizer -v
```

### 3. **Test Manual Visual** (`manual_test_visual_features.sh`)
Script interactivo para verificación visual manual:

**Ejecución**:
```bash
./manual_test_visual_features.sh
```

Este script:
- Crea imágenes de prueba automáticamente
- Ejecuta todos los comandos con diferentes configuraciones
- Muestra la salida con colores y formato
- Permite verificar visualmente cada característica
- Prueba diferentes temas y configuraciones de terminal

## 🎯 Casos de Prueba Cubiertos

### Funcionalidades Visuales
- **Temas**: Dark, Light, High Contrast, Colorblind Safe, Minimal
- **Emojis**: ✅ ❌ ⚠️ 📷 🖼️ con fallback automático
- **Progreso**: Barras, spinners, porcentajes, ETA
- **Tablas**: Bordes, alineación, estadísticas
- **Preview**: ASCII, ANSI color, Braille, Blocks, Gradient
- **TUI**: Interfaz interactiva con Textual

### Adaptación de Terminal
- **Full Featured**: iTerm2, Terminal.app con TrueColor
- **Basic**: xterm sin colores avanzados
- **No Color**: Terminales sin soporte de color
- **CI Environment**: GitHub Actions, Jenkins, etc.

### Seguridad
- **Path Traversal**: ../../../etc/passwd bloqueado
- **Command Injection**: `; rm -rf /` sanitizado
- **Rate Limiting**: 10 updates/seg máximo
- **File Size**: 100MB límite para TUI, 50MB para preview
- **Permissions**: Verificación de lectura antes de procesar

## 📊 Ejecución de Todos los Tests

```bash
# Ejecutar suite completa con reporte detallado
pytest tests/e2e/cli/ -v --tb=short --capture=no

# Con coverage
pytest tests/e2e/cli/ --cov=app.cli --cov-report=html

# Solo tests rápidos (excluir los marcados como slow)
pytest tests/e2e/cli/ -v -m "not slow"
```

## 🔍 Verificación de Resultados

Los tests validan automáticamente:

1. **Códigos ANSI**: Presencia de `\x1b[` en la salida
2. **Emojis**: Caracteres Unicode en rango `U+1F300-U+1F9FF`
3. **Tablas**: Caracteres de borde `│ ─ ┌ ┐ └ ┘`
4. **Progreso**: Caracteres `█ ▓ ▒ ░` y porcentajes
5. **Archivos**: Creación exitosa de archivos convertidos
6. **Temas**: Aplicación correcta de colores según tema

## 🐛 Debugging

Si un test falla:

1. **Verificar backend**:
   ```bash
   curl http://localhost:8080/api/health
   ```

2. **Ejecutar test individual con output**:
   ```bash
   pytest test_cli_visual_e2e.py::test_name -vvs --capture=no
   ```

3. **Ver logs del backend**:
   Check the uvicorn output for errors

4. **Ejecutar script manual**:
   ```bash
   ./manual_test_visual_features.sh
   ```

## 📈 Métricas de Éxito

- ✅ **100% de funcionalidades visuales** probadas
- ✅ **Seguridad robusta** con PathSanitizer y RateLimiter
- ✅ **Adaptación a terminal** funcionando
- ✅ **Sin regresiones** en funcionalidad base
- ✅ **Performance aceptable** (<50% overhead por visuals)

## 🎨 Capturas de Ejemplo

Los tests generan salida visual que puede ser capturada:

```bash
# Capturar salida con colores
img convert test.jpg -f webp | tee output.txt

# Convertir a HTML para visualización
cat output.txt | ansi2html > output.html
```

## 📝 Notas

- Los tests están diseñados para funcionar con el backend real
- Algunos tests pueden ser más lentos debido a operaciones reales
- El modo TUI requiere Textual instalado
- Los tests de seguridad son críticos y no deben saltarse

---

**Desarrollado para Story 6.2: Advanced UX & Visual Design** 🎨✨