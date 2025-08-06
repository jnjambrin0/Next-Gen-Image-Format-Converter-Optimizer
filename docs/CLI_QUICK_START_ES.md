# 🚀 Guía Rápida - CLI Image Converter

## Instalación Rápida (5 minutos)

### 1️⃣ Clonar y Preparar
```bash
git clone https://github.com/tu-usuario/image_converter.git
cd image_converter
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
```

### 2️⃣ Instalar Dependencias
```bash
cd backend
pip install -r requirements.txt
```

### 3️⃣ Iniciar Servidor API
```bash
# Terminal 1 - Dejar abierta
uvicorn app.main:app --reload --port 8080
```

### 4️⃣ Configurar Comando `img`
```bash
# Terminal 2 - Agregar alias
echo 'alias img="python '$(pwd)'/img.py"' >> ~/.bashrc
source ~/.bashrc
```

### 5️⃣ ¡Listo! Verificar
```bash
img --version
img --help
```

---

## 📸 Comandos Más Usados

### Convertir Una Imagen
```bash
# Básico
img convert file foto.jpg -f webp

# Con calidad
img convert file foto.jpg -f webp -q 85

# Con archivo de salida
img convert file foto.jpg -f avif -o resultado.avif
```

### Convertir Múltiples Imágenes
```bash
# Todas las JPG a WebP
img batch convert "*.jpg" -f webp

# Con procesamiento paralelo (4 hilos)
img batch convert "*.png" -f avif -j 4

# A carpeta específica
img batch convert "*.jpg" -f webp -o convertidas/
```

### Usando Atajos
```bash
img c file foto.jpg -f webp    # c = convert
img b convert "*.jpg" -f avif  # b = batch  
img o auto foto.jpg            # o = optimize
```

---

## 🔗 Encadenamiento y Pipes

### Operaciones Múltiples
```bash
# Formato + Redimensionar + Optimizar
img chain "format:webp" "resize:1920x1080" "optimize" -i foto.jpg -o resultado.webp
```

### Pipes Unix
```bash
# Pipe simple
cat imagen.jpg | img pipe -f webp > salida.webp

# Encadenar conversiones
cat foto.png | img pipe -f jpeg -q 90 | img pipe -f webp > final.webp
```

---

## ⚙️ Configuración

### Ver/Cambiar Configuración
```bash
# Ver todo
img config show

# Cambiar calidad por defecto
img config set default_quality 90

# Cambiar idioma a español
img config set language es
```

### Crear Alias Personalizados
```bash
# Crear alias "web" para conversión optimizada
img aliases add web "convert file -f webp -q 85"

# Usar el alias
img web foto.jpg
```

---

## 🆘 Solución Rápida de Problemas

| Problema | Solución |
|----------|----------|
| "API server not running" | Iniciar servidor: `cd backend && uvicorn app.main:app --port 8080` |
| "Command not found: img" | Usar ruta completa: `python /ruta/a/backend/img.py` |
| "Module not found" | Reinstalar: `pip install -r requirements.txt` |
| Error desconocido | Modo debug: `img --debug [comando]` |

---

## 📋 Tabla de Formatos

| Formato | Entrada | Salida | Mejor Para |
|---------|---------|--------|------------|
| WebP | ✅ | ✅ | Web, balance calidad/tamaño |
| AVIF | ✅ | ✅ | Máxima compresión |
| JPEG | ✅ | ✅ | Fotos, compatibilidad |
| PNG | ✅ | ✅ | Imágenes con transparencia |
| HEIF | ✅ | ✅ | Apple/iOS |
| JPEG XL | ✅ | ✅ | Próxima generación |

---

## 💡 Tips Esenciales

1. **Antes de convertir muchos archivos:**
   ```bash
   img batch convert "*.jpg" -f webp --dry-run
   ```

2. **Para procesamiento más rápido:**
   ```bash
   img batch convert "*.png" -f avif -j 8  # 8 procesos paralelos
   ```

3. **Para web optimizado:**
   ```bash
   img optimize auto foto.jpg --preset web
   ```

4. **Ver qué pasó:**
   ```bash
   img history show -n 10
   ```

5. **Deshacer si algo salió mal:**
   ```bash
   img history undo
   ```

---

## 📚 Más Ayuda

```bash
# Ayuda general
img --help

# Ayuda específica
img convert --help
img batch --help

# En español
img --lang es --help
```

---

**¡Eso es todo! Ya puedes convertir imágenes como un pro 🎉**