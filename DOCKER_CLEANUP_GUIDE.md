# 🧹 Guía de Limpieza Completa - Docker Image Converter

## ⚠️ IMPORTANTE - LEE ESTO PRIMERO

Esta guía te explica cómo **eliminar completamente** todos los recursos Docker creados por la aplicación Image Converter de tu ordenador, sin dejar ningún rastro.

## 📋 Recursos que serán creados al usar Docker

Cuando ejecutes la aplicación con Docker, se crearán los siguientes recursos en tu sistema:

### 1. **Imágenes Docker** (Espacio en disco: ~500MB - 1GB)
- `image-converter-backend` (Python + librerías)
- `image-converter-frontend` (Node + nginx)

### 2. **Contenedores Docker**
- `image_converter_backend`
- `image_converter_frontend`

### 3. **Volúmenes Docker** (Datos persistentes)
- `backend_data` - Base de datos SQLite
- `backend_logs` - Logs de la aplicación
- `backend_tmp` - Archivos temporales
- `node_modules` - Dependencias de frontend

### 4. **Redes Docker**
- `image_converter_app_network` - Red interna para comunicación

### 5. **Directorios locales** (En el proyecto)
- `./data/` - Datos de la aplicación
- `./logs/` - Archivos de log
- `./backups/` - Backups automáticos
- `./.env` - Archivo de configuración

## 🚀 Cómo probar la aplicación

### Opción 1: Entorno de Desarrollo (Recomendado para pruebas)

```bash
# 1. Iniciar Docker Desktop (asegúrate de que esté ejecutándose)

# 2. Iniciar la aplicación
./scripts/docker-dev.sh start

# 3. Acceder a la aplicación
# Frontend: http://localhost:5173
# API: http://localhost:8000
# Documentación API: http://localhost:8000/api/docs

# 4. Cuando termines, detener la aplicación
./scripts/docker-dev.sh stop
```

### Opción 2: Construcción manual

```bash
# Construir imágenes
docker-compose build

# Iniciar servicios
docker-compose up -d

# Ver logs
docker-compose logs -f

# Detener servicios
docker-compose down
```

## 🗑️ ELIMINACIÓN COMPLETA - Sin dejar rastro

### Método 1: Script Automático (RECOMENDADO)

```bash
# Ejecutar el script de limpieza completa
./scripts/docker-cleanup.sh

# El script te pedirá confirmación escribiendo 'SI ELIMINAR'
```

Este script eliminará automáticamente:
- ✅ Todos los contenedores
- ✅ Todas las imágenes
- ✅ Todos los volúmenes
- ✅ Todas las redes
- ✅ Cache de Docker
- ✅ Directorios locales

### Método 2: Limpieza Manual Paso a Paso

Si prefieres hacerlo manualmente o el script falla:

```bash
# 1. DETENER Y ELIMINAR CONTENEDORES
docker-compose down -v
docker ps -a | grep image-converter | awk '{print $1}' | xargs docker rm -f

# 2. ELIMINAR IMÁGENES
docker images | grep image-converter | awk '{print $3}' | xargs docker rmi -f

# 3. ELIMINAR VOLÚMENES
docker volume ls | grep image-converter | awk '{print $2}' | xargs docker volume rm

# 4. ELIMINAR REDES
docker network ls | grep image-converter | awk '{print $2}' | xargs docker network rm

# 5. ELIMINAR DIRECTORIOS LOCALES
rm -rf ./data ./logs ./backups
rm -f .env

# 6. LIMPIAR CACHE DE DOCKER (OPCIONAL)
docker builder prune -f
```

### Método 3: Limpieza Nuclear (ELIMINA TODO DE DOCKER)

⚠️ **ADVERTENCIA**: Esto eliminará TODOS los recursos Docker de tu sistema, no solo los de este proyecto:

```bash
# Elimina TODO de Docker (contenedores, imágenes, volúmenes, redes, cache)
docker system prune -a --volumes -f
```

## 🔍 Verificación de limpieza completa

Después de la limpieza, verifica que todo se ha eliminado:

```bash
# Verificar que no quedan contenedores
docker ps -a | grep -E "image-converter|image_converter"

# Verificar que no quedan imágenes
docker images | grep -E "image-converter|image_converter"

# Verificar que no quedan volúmenes
docker volume ls | grep -E "image-converter|image_converter"

# Verificar que no quedan redes
docker network ls | grep -E "image-converter|app_network"

# Verificar espacio en disco de Docker
docker system df

# Verificar directorios locales
ls -la ./data ./logs ./backups 2>/dev/null

# Si todos los comandos no muestran nada o dan error, ¡la limpieza fue exitosa!
```

## 📊 Espacio en disco utilizado

### Durante la ejecución:
- **Imágenes Docker**: ~500MB-1GB
- **Contenedores**: ~100MB (mientras ejecutan)
- **Volúmenes**: Variable (según uso)
- **Cache de build**: ~200MB-500MB

### Después de la limpieza:
- **Espacio liberado**: Todo el anterior
- **Rastros en el sistema**: NINGUNO

## 🆘 Solución de problemas

### Docker no está ejecutándose
```bash
# Inicia Docker Desktop primero
# En macOS: open -a Docker
```

### Permisos denegados
```bash
# Ejecuta con sudo si es necesario
sudo ./scripts/docker-cleanup.sh
```

### El script no funciona
```bash
# Dale permisos de ejecución
chmod +x ./scripts/docker-cleanup.sh

# O ejecuta con bash directamente
bash ./scripts/docker-cleanup.sh
```

### Contenedores que no se eliminan
```bash
# Forzar eliminación
docker rm -f $(docker ps -aq --filter name=image)
```

## ✅ Checklist de limpieza completa

- [ ] Docker Desktop detenido
- [ ] Todos los contenedores eliminados
- [ ] Todas las imágenes eliminadas
- [ ] Todos los volúmenes eliminados
- [ ] Todas las redes eliminadas
- [ ] Cache de Docker limpiado
- [ ] Directorios locales eliminados
- [ ] Archivo .env eliminado
- [ ] Verificación completada

## 📝 Notas importantes

1. **Backups**: Si tienes datos importantes, haz backup antes de limpiar
2. **Docker Desktop**: La limpieza NO desinstala Docker, solo elimina recursos del proyecto
3. **Código fuente**: Los archivos del proyecto NO se eliminan, solo los recursos Docker
4. **Reversibilidad**: La limpieza NO se puede deshacer

## 🎯 Resumen rápido

```bash
# Para usar la aplicación:
./scripts/docker-dev.sh start

# Para eliminar TODO sin dejar rastro:
./scripts/docker-cleanup.sh
# Escribir: SI ELIMINAR

# Verificar que todo está limpio:
docker system df
```

---

**💡 TIP**: Si solo quieres probar la aplicación temporalmente, usa el entorno de desarrollo y luego ejecuta el script de limpieza. Es la forma más segura y limpia de probar sin dejar residuos en tu sistema.