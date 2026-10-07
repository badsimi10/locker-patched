<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.
//
// Security note: password hashes use a salted, slow algorithm (bcrypt via
// password_hash), and reset tokens are random, stored server side, single use
// and same-day only. Nothing here is derived from public values, so a token
// cannot be recomputed from an email address.

function hash_password(string $password): string
{
    return password_hash($password, PASSWORD_DEFAULT);
}

function verify_password(string $password, string $stored): bool
{
    // Legacy unsalted SHA-256 hashes (64 hex chars) predate the hardening.
    // Verify them so existing accounts can still sign in; the login flow then
    // upgrades the stored hash to bcrypt (see password_needs_upgrade).
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

// A reset token is a high-entropy random value. It is never derived from the
// email or the date, so it cannot be predicted or recomputed by anyone who
// knows the account's address.
function issue_reset_token(string $email): string
{
    $token = bin2hex(random_bytes(32));
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);

    // In production this token is emailed to campus mail. There is no mail
    // service in the lab, so it is written to the server error log for a grader
    // to retrieve. It is never returned to the requester or shown in the page.
    error_log("Locker reset token for {$email}: {$token}  (open /reset?email=" . rawurlencode($email) . "&token={$token})");
    return $token;
}

// Returns true only when a token was actually issued for this email, has not
// expired (same UTC calendar day), and matches the submitted value. A valid
// consume is single use: the row is deleted so the token cannot be replayed.
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
