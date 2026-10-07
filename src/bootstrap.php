<?php
declare(strict_types=1);

// Harden the session cookie: not readable from JavaScript, not sent on
// cross-site requests, and marked Secure when the request arrived over HTTPS
// (Render terminates TLS and forwards the scheme). Secure is gated on the
// scheme so local plain-HTTP sign-in is not broken.
$https = ($_SERVER["HTTPS"] ?? "") === "on"
    || ($_SERVER["HTTP_X_FORWARDED_PROTO"] ?? "") === "https";
session_set_cookie_params([
    "httponly" => true,
    "samesite" => "Lax",
    "secure" => $https,
]);

session_start();

require __DIR__ . "/db.php";
require __DIR__ . "/crypto.php";
require __DIR__ . "/auth.php";
require __DIR__ . "/vault.php";

init_db();
seed();

function render(string $view, array $data = [], int $status = 200): void
{
    http_response_code($status);
    extract($data, EXTR_SKIP);
    $currentUser = current_user();
    require dirname(__DIR__) . "/templates/layout_start.php";
    require dirname(__DIR__) . "/templates/{$view}.php";
    require dirname(__DIR__) . "/templates/layout_end.php";
    exit;
}

function redirect(string $to): void
{
    header("Location: " . $to);
    exit;
}

function json_out(array $data): void
{
    header("Content-Type: application/json");
    echo json_encode($data);
    exit;
}

function e(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}
