<?php
declare(strict_types=1);
function hash_password(string $password): string
{
    return password_hash($password, PASSWORD_DEFAULT);
}

function verify_password(string $password, string $stored): bool
{
    if (preg_match('/^[0-9a-f]{64}$/', $stored) === 1) {
        return hash_equals($stored, hash("sha256", $password));
    }
    return password_verify($password, $stored);
}

function password_needs_upgrade(string $stored): bool
{
    if (preg_match('/^[0-9a-f]{64}$/', $stored) === 1) {
        return true;
    }
    return password_needs_rehash($stored, PASSWORD_DEFAULT);
}
function issue_reset_token(string $email): string
{
    $token = bin2hex(random_bytes(32));
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    error_log("Locker reset token for {$email}: {$token}  (open /reset?email=" . rawurlencode($email) . "&token={$token})");
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    if ($token === "") {
        return false;
    }
    $pdo = db();
    $stmt = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    if (!$row) {
        return false;
    }
    $created_day = substr((string)$row["created_at"], 0, 10);
    if ($created_day !== gmdate("Y-m-d")) {
        $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
        return false;
    }
    if (!hash_equals((string)$row["token"], $token)) {
        return false;
    }
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    return true;
}
