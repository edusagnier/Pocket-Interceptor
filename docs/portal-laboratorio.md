# Portal de laboratorio: formulario y registro de datos ficticios

## Alcance de esta entrega

La opción 6 del menú abre una simulación educativa local. Demuestra el recorrido
del formulario al registro TXT utilizando únicamente cuentas ficticias
predefinidas. La página identifica expresamente la simulación y solicita el
consentimiento del participante.

Este modo no crea un punto de acceso, no suplanta una red, no redirige tráfico
y no cambia DHCP, DNS, Apache ni firewall. El navegador debe ejecutarse en el
mismo equipo que el servidor; la dirección de escucha es exclusivamente
`127.0.0.1`. Por tanto, esta entrega valida la demostración web local, no un
portal cautivo Wi-Fi completo.

El código antiguo de `hostapd_testing.sh` y sus funciones se conserva. La opción
6 pasa a llamarse **Portal de laboratorio (cuentas ficticias, solo local)** y
ejecuta el nuevo modo. Los demás módulos mantienen su ruta de ejecución.

## Inicio rápido en Kali

Desde la raíz del repositorio, sin necesidad de root ni adaptador Wi-Fi:

```bash
python3 -B tools/lab_portal.py
```

Abre **http://127.0.0.1:8765/** en el navegador del mismo Kali. El servidor
muestra la URL efectiva y la ruta del TXT en la terminal. Se puede utilizar
también la opción 6 del menú principal; los requisitos generales de arranque
de ese menú siguen siendo los mismos.

Si el puerto está ocupado, el servidor muestra el error. Para seleccionar
automáticamente uno libre:

```bash
python3 -B tools/lab_portal.py --port 0
```

Usa entonces la URL que se haya mostrado. No se abre el navegador automáticamente.
El servidor solo necesita Python 3 y su biblioteca estándar.

## Demostración del registro

1. Escoge un alias y su clave ficticia correspondiente.
2. Marca el consentimiento de simulación.
3. Pulsa **Registrar participación de prueba**.
4. Comprueba la página de confirmación.
5. Abre el TXT cuya ruta muestra el servidor para comprobar la entrada.

| Alias | Clave ficticia |
| --- | --- |
| `participante-01` | `DEMO-01` |
| `participante-02` | `DEMO-02` |
| `participante-03` | `DEMO-03` |

Los dos campos son selectores, no entradas libres. El servidor valida también
los valores recibidos: una petición manipulada no permite almacenar otra clave,
otro alias ni campos adicionales. Las parejas incorrectas y las entradas sin
consentimiento se rechazan sin escribir datos.

Cada ejecución crea un archivo independiente:

```text
data_collected/lab_portal/simulacion_<identificador-aleatorio>.txt
```

Contiene una cabecera que identifica la simulación y una línea por envío válido,
con fecha UTC, alias ficticio y clave ficticia, separados por tabulaciones. No
se registran IP, navegador, cabeceras ni identificadores personales. Las entradas
representan envíos válidos; no equivalen a personas únicas ni permiten medir
por sí mismas quién caería en un portal engañoso real.

Los archivos se crean con permisos `600` en Linux y se conservan al detener el
servidor. `.gitignore` excluye este directorio de resultados para evitar añadir
registros generados a futuros commits. El servidor no publica archivos estáticos
ni el TXT, y sus respuestas web no se almacenan en caché.

## Cómo está organizado

| Archivo | Responsabilidad |
| --- | --- |
| `tools/lab_portal.py` | Servidor HTTP local, formulario, validación y escritura del TXT. |
| `lib/lab_portal.sh` | Lanzador desde el menú, ruta absoluta y errores de ejecución. |
| `interceptor.sh` | Conecta la opción 6 con el nuevo modo y actualiza su texto. |
| `tests/test_lab_portal.py` | Pruebas HTTP, validación, registro, cierre y lanzador. |

El servidor verifica Host, Origin y un identificador aleatorio del formulario,
rechaza campos repetidos o desconocidos y limita el tamaño del cuerpo recibido.
Una escritura fallida devuelve un error; nunca se muestra una confirmación
cuando no se ha podido registrar la participación.

## Detener y verificar

Pulsa **Ctrl+C** en la terminal del servidor. Se cierra la escucha y el TXT queda
disponible. Como este modo no cambia la red, no necesita restaurar servicios ni
reglas del sistema. Un fallo de inicio devuelve un código de error al menú.

Las pruebas del nuevo módulo realizan peticiones HTTP únicamente a un servidor
temporal en loopback y usan archivos temporales. Las pruebas del lanzador simulan
Python; no configuran ninguna interfaz ni ejecutan acciones Wi-Fi.

```bash
POCKET_TEST_BASH="$(command -v bash)" python3 -B -m unittest discover -s tests -v
bash -n interceptor.sh
bash -n lib/lab_portal.sh
```

Para probar solamente este módulo:

```bash
POCKET_TEST_BASH="$(command -v bash)" python3 -B -m unittest discover -s tests -p test_lab_portal.py -v
```

En Kali queda por confirmar visualmente la página, un envío ficticio y la salida
con Ctrl+C. No se ha validado un despliegue Wi-Fi ni una redirección de clientes.

## Resultado de las comprobaciones de desarrollo

- Las 23 pruebas del nuevo portal pasan sin omisiones, incluidas peticiones HTTP
  reales a loopback y comprobaciones del lanzador con Python simulado.
- La sintaxis de `interceptor.sh` y `lib/lab_portal.sh` es correcta.
- `git diff --check` termina sin errores.
- La suite completa ejecutó 116 pruebas: 94 pasaron y 22 fallaron en otros
  módulos. En este Windows, el Bash integrado en Visual Studio se invoca como
  `sh`, lo que rechaza funciones de prueba con guiones y sustituciones del
  builtin `trap`; también falta `sha256sum` en ese entorno. Esos fallos no se
  han ocultado ni se han modificado esos módulos como parte de esta entrega.
  La suite completa debe repetirse en Kali con un Bash completo.
