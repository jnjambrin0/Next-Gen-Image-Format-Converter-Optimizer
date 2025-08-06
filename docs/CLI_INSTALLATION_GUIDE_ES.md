# 📚 Guía Completa de Instalación y Uso del CLI de Image Converter

## 🚀 Instalación Paso a Paso

### Prerequisitos

Antes de comenzar, asegúrate de tener instalado:

- **Python 3.11 o superior**
- **pip** (gestor de paquetes de Python)
- **Git** (para clonar el repositorio)

### Paso 1: Clonar el Repositorio

```bash
# Clona el repositorio
git clone https://github.com/tu-usuario/image_converter.git

# Entra al directorio del proyecto
cd image_converter
```

### Paso 2: Crear un Entorno Virtual

Es recomendable usar un entorno virtual para evitar conflictos con otras dependencias:

```bash
# Crear entorno virtual
python -m venv venv

# Activar el entorno virtual
# En Linux/Mac:
source venv/bin/activate

# En Windows:
venv\Scripts\activate
```

### Paso 3: Instalar Dependencias del Backend

```bash
# Navegar al directorio backend
cd backend

# Instalar todas las dependencias
pip install -r requirements.txt
```

### Paso 4: Iniciar el Servidor API

El CLI necesita que el servidor API esté ejecutándose:

```bash
# Desde el directorio backend
uvicorn app.main:app --reload --port 8080
```

**Nota:** Deja esta terminal abierta con el servidor corriendo.

### Paso 5: Configurar el CLI para Uso Global (Opcional)

Abre una **nueva terminal** y navega al proyecto:

```bash
cd image_converter/backend

# Hacer el script ejecutable
chmod +x img.py

# Opción 1: Crear un alias (temporal)
alias img="python $(pwd)/img.py"

# Opción 2: Agregar al PATH permanentemente
# Agrega esta línea a tu ~/.bashrc o ~/.zshrc
export PATH="$PATH:/ruta/completa/a/image_converter/backend"
```

## 🎯 Uso Básico del CLI

### Verificar la Instalación

```bash
# Ver la versión y confirmar que funciona
python backend/img.py --version

# O si configuraste el alias/PATH
img --version
```

Deberías ver algo como:
```
Image Converter CLI    1.0.0
Python                 3.11.x
```

### Ver Ayuda General

```bash
# Ayuda principal
img --help

# Ayuda de un comando específico
img convert --help
img batch --help
```

## 📸 Comandos Principales

### 1. Convertir una Imagen Individual

```bash
# Sintaxis básica
img convert file <archivo_entrada> -f <formato_salida>

# Ejemplos prácticos:
# Convertir JPG a WebP
img convert file foto.jpg -f webp

# Convertir con calidad específica
img convert file imagen.png -f avif -q 90

# Especificar archivo de salida
img convert file foto.jpg -f webp -o mi_foto.webp

# Redimensionar durante la conversión
img convert file grande.jpg -f jpeg -w 1920 --optimize
```

### 2. Conversión por Lotes (Batch)

```bash
# Convertir todas las imágenes JPG a WebP
img batch convert "*.jpg" -f webp

# Convertir con procesamiento paralelo
img batch convert "fotos/*.png" -f avif -q 85 --parallel 4

# Guardar en directorio específico
img batch convert "*.jpg" -f webp -o convertidas/

# Procesar recursivamente
img batch convert "**/*.jpg" -f jpeg --preset web -r
```

### 3. Optimizar Imágenes

```bash
# Optimización automática
img optimize auto foto.jpg

# Optimizar con preset específico
img optimize auto imagen.png --preset web
```

### 4. Analizar Información de Imagen

```bash
# Ver información detallada de una imagen
img analyze info foto.jpg
```

### 5. Listar Formatos Soportados

```bash
# Ver todos los formatos disponibles
img formats list
```

### 6. Gestión de Presets

```bash
# Listar presets disponibles
img presets list
```

## ⚙️ Configuración del CLI

### Ver Configuración Actual

```bash
img config show
```

### Configurar la URL del API

```bash
# Si tu servidor corre en otro puerto
img config set api_url http://localhost:9000

# Ver un valor específico
img config get api_url
```

### Configurar API Key (si es necesario)

```bash
img config set api_key tu_clave_api
```

### Cambiar Idioma a Español

```bash
# Configurar idioma permanentemente
img config set language es

# O usar temporalmente
img --lang es convert file foto.jpg -f webp
```

### Resetear Configuración

```bash
img config reset
```

## 🔄 Características Avanzadas

### Usar Atajos de Comandos

El CLI incluye atajos para comandos comunes:

```bash
# Atajos incorporados
img c file foto.jpg -f webp    # 'c' = convert
img b convert "*.png" -f avif  # 'b' = batch
img o auto imagen.jpg          # 'o' = optimize
```

### Crear Tus Propios Alias

```bash
# Ver alias actuales
img aliases

# Agregar un nuevo alias
img aliases add conv convert
img aliases add opt optimize

# Usar el alias
img conv file foto.jpg -f webp

# Eliminar un alias
img aliases remove conv
```

### Encadenamiento de Comandos y Pipes

```bash
# Encadenar múltiples operaciones
img chain "format:webp" "resize:1920x1080" "optimize" -i foto.jpg -o resultado.webp

# Usar pipes estilo Unix
cat imagen.png | img pipe -f webp > salida.webp

# Convertir desde stdin
cat foto.jpg | img convert stdin -f avif -o resultado.avif
```

### Historial y Deshacer/Rehacer

```bash
# Ver historial de comandos
img history

# Ver últimos 20 comandos
img history show -n 20

# Deshacer última operación
img history undo

# Rehacer operación deshecha
img history redo

# Limpiar historial
img history clear
```

## 🔌 Sistema de Plugins

### Listar Plugins

```bash
img plugins
```

### Información de un Plugin

```bash
img plugins info nombre_plugin
```

### Habilitar/Deshabilitar Plugins

```bash
img plugins enable mi_plugin
img plugins disable mi_plugin
```

### Ubicación de Plugins

Los plugins se almacenan en: `~/.image-converter/plugins/`

## 🌍 Soporte Multi-idioma

El CLI soporta 6 idiomas:

```bash
# Cambiar idioma temporalmente
img --lang es convert file foto.jpg -f webp  # Español
img --lang fr convert file foto.jpg -f webp  # Francés
img --lang de convert file foto.jpg -f webp  # Alemán
img --lang zh convert file foto.jpg -f webp  # Chino
img --lang ja convert file foto.jpg -f webp  # Japonés

# Configurar idioma permanentemente
img config set language es
```

## 📝 Ejemplos Prácticos Comunes

### Caso 1: Optimizar Fotos para Web

```bash
# Convertir todas las fotos a WebP con calidad 85
img batch convert "fotos/*.jpg" -f webp -q 85 -o web/

# O usando un preset
img batch convert "fotos/*.jpg" -f webp --preset web
```

### Caso 2: Crear Miniaturas

```bash
# Redimensionar y convertir
img convert file foto_grande.jpg -f jpeg -w 300 -h 300 -o miniatura.jpg
```

### Caso 3: Conversión con Vista Previa (Dry Run)

```bash
# Ver qué se convertirá sin hacerlo realmente
img batch convert "*.png" -f avif --dry-run
```

### Caso 4: Procesar y Comprimir

```bash
# Encadenar formato y optimización
img chain "format:webp" "quality:80" "optimize" -i original.jpg -o final.webp
```

## 🐛 Solución de Problemas

### Error: "No se puede conectar al servidor API"

```bash
# Verificar que el servidor esté corriendo
# En otra terminal:
cd image_converter/backend
uvicorn app.main:app --reload --port 8080

# Verificar la URL configurada
img config get api_url
```

### Error: "Formato no soportado"

```bash
# Ver formatos disponibles
img formats list
```

### Error: "Comando no encontrado"

```bash
# Si no configuraste el PATH, usa la ruta completa
python /ruta/a/image_converter/backend/img.py --help

# O crea un alias
alias img="python /ruta/a/image_converter/backend/img.py"
```

### Ver Errores Detallados

```bash
# Activar modo debug para más información
img --debug convert file problemático.jpg -f webp

# O modo verbose
img --verbose convert file imagen.jpg -f webp
```

## 💡 Tips y Mejores Prácticas

1. **Usa Presets para Consistencia**: En lugar de especificar calidad cada vez, usa presets predefinidos.

2. **Procesamiento por Lotes**: Para múltiples archivos, usa `batch` en lugar de múltiples comandos `convert`.

3. **Dry Run Primero**: Usa `--dry-run` para verificar qué se procesará antes de ejecutar operaciones grandes.

4. **Historial para Repetir**: Usa el historial para repetir comandos complejos.

5. **Pipes para Automatización**: Integra el CLI con otros comandos Unix usando pipes.

## 📊 Tabla de Referencia Rápida

| Comando | Atajo | Descripción |
|---------|-------|-------------|
| `img convert file` | `img c file` | Convertir imagen individual |
| `img batch convert` | `img b convert` | Conversión por lotes |
| `img optimize auto` | `img o auto` | Optimizar automáticamente |
| `img analyze info` | `img a info` | Analizar imagen |
| `img formats list` | `img f list` | Listar formatos |
| `img presets list` | `img p list` | Listar presets |

## 🔧 Configuración Avanzada

### Archivos de Configuración

La configuración se almacena en:
- `~/.image-converter/config.json` - Configuración principal
- `~/.image-converter/aliases.json` - Alias personalizados
- `~/.image-converter/history/` - Historial de comandos
- `~/.image-converter/plugins/` - Plugins instalados

### Variables de Entorno

También puedes configurar mediante variables de entorno:

```bash
export IMAGE_CONVERTER_API_URL="http://localhost:8080"
export IMAGE_CONVERTER_API_KEY="tu_clave"
export IMAGE_CONVERTER_LANGUAGE="es"
```

## 📚 Recursos Adicionales

- **Documentación completa**: `docs/`
- **Ejemplos de plugins**: `backend/app/cli/plugins/interface.py`
- **Tests**: `backend/tests/unit/cli/` y `backend/tests/integration/cli/`

## 🎉 ¡Listo para Usar!

Ya tienes todo configurado para usar el CLI de Image Converter. Comienza con comandos simples y explora las características avanzadas a medida que te familiarices con la herramienta.

### Comando de Inicio Rápido

```bash
# Tu primer conversión
img convert file mi_foto.jpg -f webp -q 85 -o mi_foto_optimizada.webp
```

¡Disfruta convirtiendo y optimizando tus imágenes! 🖼️✨