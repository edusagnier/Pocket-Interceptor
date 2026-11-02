# Versión: recuperación de las sesiones del portal

Fecha: 2 de noviembre de 2026. Primer bloque de mejoras de calidad.
Esta entrega no asigna un número de versión global al proyecto.

## Resumen

Esta versión incorpora un ciclo de sesión compartido para guardar el estado del
equipo antes de ejecutar el portal y recuperarlo al terminar. Su objetivo es
reducir los efectos persistentes de una salida normal, un error o una interrupción.
Mantiene las opciones existentes; no añade nuevos módulos de pentesting.

## Problema y alcance

Antes, `hostapd_testing.sh` registraba la limpieza después de ejecutar el portal.
La limpieza vaciaba toda la tabla NAT, imponía un valor fijo de forwarding,
detenía servicios sin recordar su estado y borraba archivos de `templates/`.

Este bloque protege `false_ap` en ambos scripts mediante `lib/session.sh` y
`tools/session_state.py`. Conserva las opciones del menú y los módulos existentes.
No corrige todavía los parámetros fijos del script de pruebas, el cambio de
variante, el parser Nmap ni las operaciones de modo monitor del menú principal.

## Archivos de esta entrega

| Archivo | Responsabilidad o cambio |
| --- | --- |
| `interceptor.sh` | Carga la biblioteca y conecta su función de portal con el ciclo de sesión. |
| `hostapd_testing.sh` | Aplica el mismo ciclo al portal que ejecuta actualmente el menú. |
| `lib/session.sh` | Gestiona el bloqueo, las trampas, el proceso hijo y los permisos. |
| `tools/session_state.py` | Guarda el estado y ejecuta las operaciones de recuperación. Usa únicamente la biblioteca estándar de Python. |
| `tests/test_session_state.py` | Prueba recuperación y trampas con comandos de administración simulados. |
| `requirements.txt` | Añade los paquetes APT `python3` y `util-linux`. |
| `.gitattributes` | Establece finales de línea LF para Bash y Python en los checkouts de Git. |
| `docs/cambios-sesion.md` | Describe esta entrega, su funcionamiento, verificación y límites. |
| `README.md` | Incluye el enlace a esta explicación. |

## Cómo funciona

### 1. Inicio y copia del estado

`false_ap` se ejecuta en una subshell y llama a `session_begin` antes de detener
servicios. La biblioteca comprueba que se ejecuta como root y adquiere un bloqueo
exclusivo mediante `flock`. Después crea un directorio de sesión con nombre
aleatorio y permisos restrictivos.

El ayudante Python consulta los estados de servicios, el forwarding y la interfaz,
y guarda copias de los archivos conocidos. Solo cuando termina esa preparación
se registran las trampas y se permite continuar. Si la preparación falla, el
portal devuelve un error sin iniciar sus cambios de red o servicios.

La estructura de una sesión es la siguiente; `ID` representa el nombre aleatorio:

```text
/tmp/pocket-interceptor.ID/
├── state.json               # Estado inicial y operaciones registradas
├── backups/                 # Copias privadas de archivos previos
├── addresses                # Copia binaria de direcciones de la interfaz
├── routes                   # Copia binaria de rutas IPv4
├── routes6                  # Copia binaria de rutas IPv6
├── generated/               # Configuraciones y páginas temporales
└── results/
    └── credentials.log      # Resultados nuevos; no se borran al salir
```

La carpeta de resultados se crea durante la preparación de los archivos web.
Las copias de configuración y el diario siguen siendo privados para root;
el usuario web recibe acceso únicamente al directorio de resultados y permiso
de paso por el directorio de sesión.

### 2. Registro durante la ejecución

Los cambios de servicios pasan por `session_service`, que anota el servicio antes
de intentar la operación. Antes de alterar la interfaz o el forwarding se registra
que será necesario restaurarlos. El diario se escribe en un archivo temporal,
se sincroniza y se sustituye mediante un renombrado.

`session_iptables` añade a las reglas un comentario con un identificador único.
Las llamadas del PHP generado reciben el mismo identificador al preparar sus
archivos. Ese identificador permite distinguir las reglas de esta sesión de las
que ya existían.

`session_run_foreground` conserva el PID del proceso de `hostapd` mientras espera
su finalización. Esto permite detener ese proceso concreto antes de recuperar
la configuración.

### 3. Salida y restauración

La trampa de salida se ejecuta también cuando la función retorna. Las señales
SIGINT, SIGTERM y SIGHUP provocan una salida con códigos 130, 143 y 129,
respectivamente, y activan la misma recuperación.

El orden de recuperación es:

1. Terminar y esperar al proceso hijo registrado si continúa en ejecución.
2. Detener los servicios que la sesión haya utilizado.
3. Eliminar las reglas cuyo comentario coincida exactamente con la sesión.
4. Recuperar el forwarding, los archivos y los enlaces Apache registrados.
5. Recuperar tipo, direcciones, estado administrativo y rutas de la interfaz,
   si el portal intentó modificarla.
6. Iniciar los servicios utilizados que estaban activos antes de comenzar.

Un fallo de recuperación no impide intentar las operaciones restantes. Si todo
termina correctamente, el diario se marca como finalizado: un segundo intento
no vuelve a modificar el sistema. Si hay errores, se conserva pendiente para
permitir un reintento.

Se mantiene el código de error original de la ejecución. Si la ejecución había
terminado correctamente pero falla la recuperación, se devuelve un error.
Al terminar se muestra la ruta del registro, que también permite localizar
los resultados de esa sesión.

## Modificaciones

- La sesión guarda el estado antes de detener servicios o cambiar la interfaz.
  Si no puede completar la copia, el portal no se inicia.
- El portal se ejecuta en una subshell con limpieza en salida normal, error,
  SIGINT, SIGTERM y SIGHUP. Conserva el código de error original. Un fallo de
  restauración convierte una salida inicialmente correcta en un error.
- Una cerradura con `flock` en `/run/pocket-interceptor.lock` impide que dos
  sesiones del portal sobrescriban sus respectivas copias de recuperación.
- Se registran los servicios afectados antes de cada operación. En la salida
  se detienen los consumidores, se restaura la configuración y se vuelven a
  iniciar los servicios que estaban activos. Los servicios inicialmente
  inactivos o fallidos quedan detenidos; no se recrea su estado interno de fallo.
- Se guardan el tipo y estado administrativo de la interfaz, sus direcciones
  y sus rutas IPv4/IPv6 mediante las herramientas de Linux. Solo se restaura
  la interfaz si el portal intentó modificarla.
- Las reglas creadas desde Bash y el PHP generado llevan un identificador de
  sesión. La limpieza elimina únicamente reglas con ese identificador exacto.
  No usa `iptables -F` ni restaura una instantánea global del firewall.
- El valor anterior de `net.ipv4.ip_forward` se recupera cuando fue modificado.
- Las configuraciones, los certificados y los archivos web conocidos se copian
  antes de modificarlos; se recuperan contenido y metadatos. Los archivos que
  no existían se retiran por su ruta exacta. Se rechazan destinos simbólicos
  para evitar sobrescribir un objetivo que no haya sido copiado.
- Se registran los enlaces de Apache creados por sus comandos de configuración;
  se retiran esos enlaces y se recuperan los enlaces iniciales eliminados.
- Los archivos generados van a una carpeta de sesión en `/tmp`, no a `templates/`.
  Las copias privadas se conservan para diagnóstico o recuperación manual.
- Se elimina el cambio recursivo a permisos `777` y la modificación indiscriminada
  del propietario de todos los archivos web. La clave privada copiada para BEeF
  queda accesible solamente para su propietario de servicio.
- Los nuevos resultados se guardan en `results/credentials.log` dentro de la
  carpeta de sesión, fuera del directorio público de Apache. Solo el usuario
  web y root tienen acceso al directorio de resultados. No se elimina ni se
  migra un `creds.txt` que ya existiera en una instalación anterior.
- El proceso de `hostapd` se identifica y termina antes de restaurar el sistema
  cuando se interrumpe la ejecución. No se utiliza una terminación global de procesos.
- Se corrige el separador ausente en el destino de configuración de Apache,
  necesario para escribir y restaurar los archivos previstos.
- Se añaden Python 3 y util-linux al manifiesto APT, y reglas de finales LF
  para los archivos Bash y Python en `.gitattributes`.

## Verificación automatizada

Desde la raíz del repositorio:

```sh
python3 -B -m unittest discover -s tests -v
```

Las pruebas Python simulan todos los comandos de administración. Solo utilizan
archivos temporales. Incluyen restauración de archivos, conservación de recursos
ajenos, reintentos tras fallos, estado de servicios, forwarding, interfaz y rutas,
así como selección exacta de reglas del firewall.

Para incluir las pruebas de trampas y procesos Bash:

```sh
POCKET_TEST_BASH="$(command -v bash)" python3 -B -m unittest discover -s tests -v
```

Las pruebas Bash sustituyen el ayudante de administración por una función
simulada. Comprueban salidas normales, errores, señales, retornos desde una
subshell, sustitución de marcadores y el proceso hijo identificado.

Comprobación de sintaxis, sin ejecutar los módulos:

```sh
bash -n interceptor.sh
bash -n hostapd_testing.sh
bash -n lib/session.sh
```

La ejecución de desarrollo se realiza desde Windows con el Bash incluido en
Visual Studio. No se han ejecutado servicios Linux, cambios de firewall,
escaneos de red ni operaciones Wi-Fi reales.

Resultado del bloque: 27 pruebas superadas, sin omisiones al proporcionar
`POCKET_TEST_BASH`; comprobación de sintaxis de los tres scripts superada;
`git diff --check` sin errores. El ejecutable de Bash y sus utilidades deben
estar en PATH durante las pruebas; el lanzador de la suite añade su directorio.

## Recuperación y límites

El programa muestra la ruta de su registro privado. Ante una restauración
incompleta, conserva el registro y permite reintentar en el mismo sistema:

```sh
sudo python3 tools/session_state.py finish /tmp/pocket-interceptor.ID_DE_LA_SESION
```

Usar la ruta exacta que haya mostrado el programa. Las copias contienen
configuración y pueden contener claves privadas: mantenerlas protegidas y
retenerlas solo durante el tiempo necesario. `/tmp` no es almacenamiento
duradero y el sistema puede limpiarlo durante un reinicio.

SIGKILL, un apagado y un fallo del sistema no permiten ejecutar trampas. No
modificar en paralelo los mismos archivos, interfaces o servicios desde otras
herramientas: su restauración presupone que siguen perteneciendo a esta sesión.
Las copias binarias de direcciones y rutas requieren la misma interfaz e índice
de dispositivo; no garantizan recuperación después de desconectar el adaptador
o reiniciar el equipo. No se guardan asociaciones Wi-Fi, concesiones DHCP ni el
estado interno completo de NetworkManager.

Antes de considerar validada la integración, falta comprobar en una VM Kali
con instantánea la entrada, salida e interrupción del portal, las configuraciones
Apache, los permisos efectivos del proceso web y la restauración de red con el
adaptador previsto. Las pruebas simuladas no demuestran compatibilidad con el
hardware ni que todas las funcionalidades del proyecto funcionen.
