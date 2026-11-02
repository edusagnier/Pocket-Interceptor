# Pantalla de progreso del análisis local de handshake

Antes, `Craking_handshake` redirigía la salida completa a un archivo y el usuario
no veía el estado durante el análisis. Ahora muestra la interfaz de terminal
que ofrece la herramienta y conserva una copia de su salida.

El decoder utiliza una ventana independiente (o un panel dentro de tmux).
En escritorios X11 con `wmctrl`, su ventana se coloca en la mitad derecha
del área de trabajo, sin mover otras ventanas. En Wayland o sin `wmctrl`,
la ubicación depende del gestor de ventanas. Si no puede abrir una vista
separada, conserva el progreso en la pantalla principal.

Al terminar, la ventana del decoder permanece abierta hasta pulsar Enter.
Si Aircrack-ng informa `KEY FOUND!`, se muestra la línea con su resultado
tanto allí como en la pantalla principal. No se añade una animación simulada
ni se cambia el proceso de análisis: se presenta la salida real de la herramienta.

## Funcionamiento

`lib/live_output.sh` utiliza `script` de util-linux para proporcionar una
terminal virtual. Así la herramienta conserva su presentación de terminal,
mientras el registro se guarda en `data_collected/network_dump/` con un nombre
aleatorio `result_handshake_XXXXXXXX.txt`. El comando se construye con argumentos
escapados para Bash y el visor devuelve el código de salida del proceso.

La pantalla muestra las métricas que publique la versión instalada de Aircrack-ng.
No representa un descifrado progresivo carácter a carácter ni garantiza mostrar
todas las palabras que se prueban. Tampoco garantiza encontrar una coincidencia.

Antes de iniciar, se comprueba la presencia de la herramienta y que la captura
y el diccionario sean archivos legibles y no vacíos. Al terminar se muestra la
ruta del registro y se espera a Enter en una terminal interactiva para que el
menú no borre inmediatamente el resultado. Un fallo devuelve el control al menú.

## Detener el análisis

Durante la vista se indica que se puede cancelar con `Ctrl+C`. El visor conserva
su PID y registra manejadores para SIGINT, SIGTERM y SIGHUP. Al recibir una de
estas señales, solicita la terminación del visor y espera a que limpie el proceso
de su terminal virtual antes de devolver el control. No utiliza `pkill` ni termina
otras sesiones por nombre.

El comando de la terminal virtual utiliza `exec` para reemplazar el shell
intermedio; esto permite que la limpieza de util-linux se dirija al proceso local
que está mostrando. Los códigos de cancelación son 130, 143 y 129 respectivamente.
La pantalla informa de la interrupción y conserva captura y registro parcial.
Las trampas no pueden actuar si se mata directamente el proceso con SIGKILL o se
apaga el equipo.

Las pruebas de señales crean un visor simulado, le envían señales reales y
comprueban que se espera su salida y que ya no queda en ejecución. No ejecutan
Aircrack-ng: la interacción real entre Ctrl+C, util-linux y la terminal debe
confirmarse en Kali.

Los registros se crean con permisos privados, pues pueden contener información
sensible. Conservan los caracteres de control usados para dibujar la pantalla.
La captura se conserva también cuando no hay coincidencia o se cancela: ya no
se borran los archivos `wificapture-01.*` al salir de esta función.

Este cambio afecta únicamente a la presentación del análisis local existente;
no cambia la captura, el diccionario predeterminado ni las opciones de análisis.

## Verificación

Las pruebas usan archivos ficticios y una herramienta simulada. No se utilizan
capturas reales ni se ejecutan operaciones Wi-Fi.

```bash
POCKET_TEST_BASH="$(command -v bash)" python3 -B -m unittest discover -s tests -v
bash -n interceptor.sh
bash -n lib/live_output.sh
```

La presentación visual real necesita comprobarse en una terminal Kali.
Las pruebas cubren la apertura independiente, el resultado encontrado, la
posición a la derecha con un gestor X11 simulado y la cancelación sin dejar
abierto el visor. También se comprueba la sintaxis de los scripts modificados.

Referencia del visor: [manual de script](https://man7.org/linux/man-pages/man1/script.1.html).
