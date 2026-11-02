# Diagnóstico del escáner (opción 8)

La opción 8 no necesita una contraseña Wi-Fi como entrada. Necesita acceso
autorizado a la red o al dispositivo que se quiere analizar. La conectividad
del equipo y la autenticación a su red se gestionan fuera de este módulo.

## Cambios

- El menú invoca explícitamente Python 3 y usa la ruta del proyecto. No depende
  del permiso ejecutable de `netscan.py` ni del directorio desde el que se lance.
- Antes de volver al menú principal se espera a Enter en una terminal interactiva,
  para no borrar inmediatamente los mensajes y resultados.
- Se informa si falta Python 3, el archivo del escáner, Nmap o Bash para descubrimiento.
- Las direcciones IPv4 y los prefijos se validan antes de ejecutar comandos.
- Los errores de Nmap, permisos insuficientes, tiempo de espera y salida vacía
  se distinguen de una ejecución válida. Los errores esperados permiten volver
  al menú del escáner sin un traceback.
- Si falta Requests, sigue disponible el análisis local; las consultas CVE se
  identifican como no disponibles.
- Una consulta NVD fallida o incomprensible no se interpreta como ausencia de
  vulnerabilidades. Los errores HTTP se resumen sin imprimir claves ni los
  detalles internos de las excepciones de la conexión.
- Se avisa cuando el parser no logra extraer dispositivos: su salida vacía no
  demuestra que la red esté vacía. La sustitución del parser sigue pendiente.
- El descubrimiento se ejecuta desde la carpeta del proyecto y propaga su fallo.
  Sus limitaciones anteriores (selección de red y directorios de salida) no se
  han corregido en este bloque.

No se modifican las opciones 6, 7 y 10 ni sus requisitos o lógica de ejecución.

## Pruebas

```bash
POCKET_TEST_BASH="$(command -v bash)" python3 -B -m unittest discover -s tests -v
bash -n interceptor.sh
bash -n lib/scanner.sh
```

Los comandos externos y las consultas HTTP se simulan. No se ejecutan escaneos
de red reales. Se prueban dependencias ausentes, direcciones inválidas, permisos,
timeout, códigos de salida, fallos NVD y ejecución desde otro directorio.

Resultado: 44 pruebas superadas sin omisiones al proporcionar `POCKET_TEST_BASH`,
sintaxis Bash correcta y `git diff --check` sin errores. Se han añadido 17 pruebas
a las 27 existentes. La integración real del escáner en Kali queda pendiente.
