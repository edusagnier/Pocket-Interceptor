# Escaneo, terminales y decoder

Comparado con `b488916` (`HEAD~2` al realizar el cambio). Se mantienen los diez
segundos y las opciones del escaneo anterior, con resultados privados por ejecución.

`lib/process_view.sh` abre una vista independiente para cada proceso:

- Dentro de tmux, divide la ventana en paneles visibles simultáneamente.
- En escritorio, abre ventanas de GNOME Terminal o del emulador predeterminado.
- Sin entorno gráfico o si el emulador no arranca el comando, usa la pantalla
  principal. No depende de wmctrl, del título ni de la resolución del monitor.

El proceso confirma que ha arrancado. Si no lo hace en tres segundos, se utiliza
la pantalla principal. Una marca atómica evita ejecutar dos veces el mismo comando
si la terminal responde tarde. El padre espera el resultado real del comando y
conserva su código de salida, incluso cuando el emulador usa un servidor externo.
Cerrar la vista antes de terminar se comunica como un error.

Para ver paneles simultáneos en una consola o por SSH:

```bash
sudo tmux new-session -s pocket 'bash ./interceptor.sh'
```

Si tmux no está instalado, es opcional (`sudo apt install tmux`). En escritorio
se abren ventanas independientes, que se pueden colocar lado a lado. No se exige
un emulador concreto que soporte pestañas. Para forzar la pantalla principal:

```bash
sudo POCKET_TERMINAL_MODE=inline bash ./interceptor.sh
```

El escaneo, la captura, el proceso de radio existente y el decoder comparten este
mecanismo. Los dos procesos de captura se esperan antes de abrir el decoder;
un fallo ya no se oculta con una espera fija. Sin vistas independientes, ambas
salidas pueden intercalarse en la pantalla principal. El decoder sigue mostrando
su interfaz nativa mediante util-linux `script`, conserva el registro privado y
no elimina la captura.

## Error de wlan0mon

Una ventana distinta no corrige un error `ioctl(SIOCSIFFLAGS): Protocol error`.
Antes del escaneo se consulta `iw dev INTERFAZ info` y se exige modo monitor.
Esta comprobación solo lee el modo: no consulta ni modifica el enlace mediante
`ip`. Tras verificarlo se inicia airodump-ng, como en el flujo anterior. Si el
escáner falla, se comunica su código de salida sin leer CSV antiguos.

Cada escaneo conserva stderr en `discovery_XXXXXXXX/scan.stderr.log`, dentro
del directorio privado de resultados. Si falla, la pantalla principal muestra
las últimas 40 líneas y la ruta completa del registro, aunque la ventana del
escaneo se haya cerrado. Se distingue entre un fallo antes de ejecutar la
herramienta y un fallo de la herramienta. Los mensajes de inicialización o
`SIOCSIFFLAGS` se muestran como tales; no se atribuye su causa a un controlador
concreto sin diagnósticos del equipo real.

La opción 2 del menú consulta el modo real y busca la interfaz monitor en el
mismo adaptador físico. No presupone que se llame wlan0mon. Al repetir esa opción
no modifica el enlace de una interfaz que ya está en modo monitor. La activación
mediante airmon-ng sigue teniendo los efectos sobre servicios que tenía antes.

Si persiste el error, hacen falta los diagnósticos de la máquina con la tarjeta:

```bash
iw dev
ip link show
rfkill list
sudo dmesg | tail -n 40
```

Un bloqueo de radio, un controlador o un adaptador USB desconectado necesita
resolverse en esa máquina; no se reinicia el controlador automáticamente.

## Verificación

```bash
POCKET_TEST_BASH="$(command -v bash)" python3 -B -m unittest discover -s tests -v
bash -n interceptor.sh
bash -n lib/process_view.sh
bash -n lib/process_worker.sh
bash -n lib/live_output.sh
bash -n lib/wireless_scan.sh
```

Las pruebas usan comandos simulados y archivos sintéticos, sin tráfico de red.
La validación con tarjeta Wi-Fi, emulador gráfico y tmux reales queda pendiente
para el equipo Linux de destino.

`tests/test_startup_discovery.py` ejecuta el programa completo en una copia
temporal: arranque, selección de interfaz, menú, opción 4, listado y selección
de la primera red (ID 0). Cubre una interfaz monitor previa al arranque, tanto
con nombre `wlan0mon` como `wlan0`, y una interfaz managed cuyo nombre termina
en `mon`. Verifica que el flujo no llama a airmon-ng ni cambia el enlace.
También comprueba la ruta de ventana independiente y el fallback con lanzadores
simulados. Se corrigió la validación que rechazaba el ID 0 mostrado en la lista.

La [transcripción de la prueba](../artifacts/startup-monitor-verification.txt)
permite revisar el texto del menú y del listado. Es una ejecución con interfaz,
red y ventana simuladas; no es una captura de pantalla del equipo Linux.
