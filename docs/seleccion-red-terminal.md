# Corrección de la pantalla de búsqueda de redes

En `Select wireless network`, la ruta gráfica abría un emulador externo y
buscaba su ventana por título mediante `wmctrl`. Si no localizaba el título,
mostraba «No se pudo encontrar la ventana de la terminal». Esa ruta también
contenía una comilla sobrante al final del comando construido como texto.

El descubrimiento utiliza ahora `lib/wireless_scan.sh` y muestra el escaneo
en la terminal actual. No necesita emulador gráfico, Qt, `wmctrl` ni resolución
de pantalla. El cambio no modifica la función compartida `open_terminal` ni
los módulos de deautenticación o portal.

Se conservan los diez segundos y las opciones anteriores de observación.
El límite temporal esperado (código 124 de GNU timeout) permite continuar;
los demás errores se muestran antes de volver al menú. Ctrl+C se interpreta
como cancelación cuando devuelve el código 130. No se cambia el modo de la
interfaz ni se detienen servicios desde este ayudante.

Cada ejecución escribe en un subdirectorio privado y nuevo de
`data_collected/network_dump/discovery_XXXXXXXX/`. Solo se utiliza el CSV de
esa ejecución, evitando leer un resultado viejo si el nuevo escaneo falla.
Se comprueban herramientas, escritura del directorio y presencia del CSV.

La selección lee el archivo por su ruta absoluta y no cambia el directorio
de trabajo. La lógica posterior de selección y contraseña se mantiene.
Esta entrega no corrige las limitaciones del parser CSV ni su validación
del índice cero, que siguen pendientes.

## Verificación

```bash
POCKET_TEST_BASH="$(command -v bash)" python3 -B -m unittest discover -s tests -v
bash -n interceptor.sh
bash -n lib/wireless_scan.sh
```

Las pruebas simulan el escáner y no usan interfaces reales ni acciones de red.
La comprobación visual de esta pantalla queda pendiente en la terminal Kali.
Resultado de desarrollo: 61 pruebas superadas sin omisiones y sintaxis Bash
correcta. Ocho pruebas nuevas cubren el descubrimiento sin interfaz gráfica,
errores, cancelación, argumentos y rechazo de resultados antiguos.
