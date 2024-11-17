
# LeviathanMapper

**LeviathanMapper** es una herramienta en Golang para la enumeración de subdominios. Inspirada en mitos y leyendas marinas, esta herramienta explora las profundidades de los dominios para encontrar subdominios a través de múltiples fuentes públicas y APIs. Es ideal para profesionales de ciberseguridad, pentesters y cualquier persona interesada en el reconocimiento de dominios.

## Características

- Consulta fuentes públicas como **Crt.sh**.
- Integración opcional con APIs como:
  - **SecurityTrails**
  - **Shodan**
  - **Amass**
- Prevención de duplicados en los resultados.
- Validación de subdominios activos.
- Resultados agrupados y presentados al final de la ejecución.
- Compatible con proxies para consultas anónimas.
- Modo básico disponible si no se configuran las claves API.

## Requisitos

1. **Golang 1.19+** instalado.
2. Claves API opcionales para:
   - SecurityTrails
   - Shodan
   - Amass

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu-usuario/LeviathanMapper.git
   cd LeviathanMapper
   ```

2. Instala las dependencias necesarias:
   ```bash
   go mod tidy
   ```

3. Compila el proyecto (opcional):
   ```bash
   go build -o leviathan
   ```

## Configuración

### Configuración de Claves API (opcional)

Si deseas usar las funcionalidades avanzadas con APIs, configura las siguientes claves como variables de entorno:

```bash
export SECURITYTRAILS_API_KEY=your_securitytrails_api_key
export SHODAN_API_KEY=your_shodan_api_key
export AMASS_API_KEY=your_amass_api_key
```

Si no configuras las claves, la herramienta funcionará en modo básico utilizando únicamente fuentes públicas.

---

## Uso

### Ejecución Básica

Ejecuta el programa proporcionando un dominio objetivo con la bandera `-domain`:

```bash
go run LeviathanMapper.go -domain example.com
```

### Opciones Disponibles

| Opción         | Descripción                                           | Ejemplo                              |
|-----------------|-------------------------------------------------------|--------------------------------------|
| `-domain`      | Dominio objetivo para buscar subdominios              | `-domain example.com`               |
| `-concurrency` | Número de goroutines para ejecutar consultas en paralelo | `-concurrency 50`                   |
| `-proxy`       | URL del proxy para anonimizar consultas               | `-proxy http://127.0.0.1:8080`       |

### Ejemplos de Uso

1. **Búsqueda básica de subdominios**:
   ```bash
   go run LeviathanMapper.go -domain example.com
   ```

2. **Aumentar la concurrencia para búsquedas más rápidas**:
   ```bash
   go run LeviathanMapper.go -domain example.com -concurrency 50
   ```

3. **Usar un proxy para las consultas**:
   ```bash
   go run LeviathanMapper.go -domain example.com -proxy http://127.0.0.1:8080
   ```

4. **Ejecución desde el binario compilado**:
   ```bash
   ./leviathan -domain example.com
   ```

---

## Ejemplo de Salida

```plaintext
Subdominio encontrado: sub1.example.com
Subdominio encontrado: sub2.example.com

=== Subdominios encontrados ===
sub1.example.com
sub2.example.com
==============================
```

---

## Funcionalidades Futuras

- Exportación de resultados a formatos CSV y JSON.
- Mayor integración con APIs adicionales.
- Detección de subdominios históricos.
- Implementación de pruebas automáticas.

---

## Contribuciones

Si deseas contribuir al proyecto, abre un issue o envía un pull request. ¡Toda ayuda es bienvenida!

---

## Licencia

Este proyecto está licenciado bajo la [MIT License](LICENSE).

---

## Contacto

Cualquier duda o sugerencia, no dudes en contactarme a través de [mi perfil de GitHub](https://github.com/tu-usuario).
