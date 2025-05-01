<?php
// Configuración
$portal_url = "http://192.168.1.1/index.php";
$essid = "PI_WIFI_TEST";

// Detectar si el cliente ya está autenticado
if (isset($_COOKIE['auth']) && $_COOKIE['auth'] === 'ok') {
    // Responder a comprobaciones de sistema operativo con "éxito"
    if (strpos($_SERVER['REQUEST_URI'], '/generate_204') !== false) {
        http_response_code(204);  // Android
        exit;
    }

    if (strpos($_SERVER['REQUEST_URI'], 'hotspot-detect.html') !== false) {
        echo "Success";  // Apple
        exit;
    }

    if (strpos($_SERVER['REQUEST_URI'], 'connecttest.txt') !== false) {
        echo "Microsoft Connect Test";  // Windows
        exit;
    }
}

// Detección mejorada
$userAgent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$requestUri = strtolower($_SERVER['REQUEST_URI'] ?? '');

$captive_checks = [
    'captivenetworksupport',
    'wispr',
    'android',
    'microsoft ncsi',
    'ms-office',
    'xbox'
];

$test_paths = [
    '/generate_204',
    '/hotspot-detect.html',
    '/ncsi.txt',
    '/connecttest.txt',
    '/connectivity-check.html'
];

if (in_array($requestUri, $test_paths)) {
    header("Location: $portal_url");
    exit;
}

foreach ($captive_checks as $check) {
    if (strpos($userAgent, $check) !== false) {
        header("Location: $portal_url");
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Required - <?php echo htmlspecialchars($essid); ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="portal">
        <h1>WiFi Login - <?php echo htmlspecialchars($essid); ?></h1>
        <form action="register.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="email" name="email" placeholder="Email" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>
