<?php
// =============================================
// login.php - Login page
// =============================================

require_once 'config.php';

// If already logged in, go straight to profile
if (isset($_SESSION['user_id']) && isset($_SESSION['otp_verified'])) {
    header('Location: profile.php');
    exit;
}

// If they passed step 1 (email/password) but not step 2 (OTP), send to OTP page
if (isset($_SESSION['waiting_for_otp'])) {
    header('Location: verify.php');
    exit;
}

$error   = '';
$warning = '';

// =============================================
// Handle the login form when submitted
// =============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password']   ?? '';
    $ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    $db = connect_db();

    // --- Check if this email is currently locked out ---
    // Count failed attempts in the last 5 minutes
    $five_min_ago = date('Y-m-d H:i:s', time() - 300);

    $stmt = $db->prepare("
        SELECT COUNT(*) as total, MAX(attempt_time) as last_try
        FROM login_attempts
        WHERE email = ? AND attempt_time > ?
    ");
    $stmt->execute([$email, $five_min_ago]);
    $attempts = $stmt->fetch();

    // If they failed 3+ times, check if lockout is still active
    if ($attempts['total'] >= MAX_LOGIN_TRIES) {
        $last_try       = strtotime($attempts['last_try']);
        $seconds_passed = time() - $last_try;
        $seconds_left   = LOCKOUT_TIME - $seconds_passed;

        if ($seconds_left > 0) {
            // Still locked out — tell the page how many seconds remain
            $lockout_remaining = $seconds_left;
            $error = "Too many failed attempts. Please wait {$seconds_left} seconds.";
        } else {
            // Lockout expired — delete old failed attempts so they can try again
            $db->prepare("DELETE FROM login_attempts WHERE email = ?")->execute([$email]);
        }
    }

    // --- If not locked out, check the email and password ---
    if (empty($error)) {

        // Look up the user by email
        $stmt = $db->prepare("SELECT * FROM users WHERE email = ? LIMIT 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        // Check if user exists and password matches
        // Apply the same pepper used during registration for verification
        $password_with_pepper = $password . PASSWORD_PEPPER;
        if ($user && password_verify($password_with_pepper, $user['password'])) {
            // ✅ Password correct! Generate OTP
            $otp_code = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $expires  = date('Y-m-d H:i:s', time() + OTP_EXPIRE);
            
            // Set session BEFORE emailing so the page loads instantly
            $_SESSION['waiting_for_otp'] = true;
            $_SESSION['temp_user_id']    = $user['id'];
            $_SESSION['temp_user_name']  = $user['first_name'];
            
            // Delete old OTP and save new one
            $db->prepare("DELETE FROM otp_tokens WHERE user_id = ?")->execute([$user['id']]);
            $db->prepare("INSERT INTO otp_tokens (user_id, otp_code, expires_at) VALUES (?, ?, ?)")
               ->execute([$user['id'], $otp_code, $expires]);
            
            // Send email — redirect to verify page regardless of send result
            // (user can click Resend if it doesn't arrive)
            require_once 'mailer.php';
            send_otp_email($user['email'], $user['first_name'], $otp_code);
            
            header('Location: verify.php');
            exit;

        } else {
            // ❌ Wrong email or password — log this failed attempt
            $db->prepare("
                INSERT INTO login_attempts (email, ip_address) VALUES (?, ?)
            ")->execute([$email, $ip]);

            // Count how many tries they have left
            $stmt = $db->prepare("
                SELECT COUNT(*) as total FROM login_attempts
                WHERE email = ? AND attempt_time > ?
            ");
            $stmt->execute([$email, $five_min_ago]);
            $count = $stmt->fetch()['total'];
            $left  = max(0, MAX_LOGIN_TRIES - $count);

            $error = $left > 0
                ? "Wrong email or password. You have {$left} attempt(s) left."
                : "Too many failed attempts. Please wait " . LOCKOUT_TIME . " seconds.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <title>Login - MyApp</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="auth-page">

<div class="auth-card">

    <!-- App logo -->
    <div class="auth-logo"><div class="auth-logo-mark">🔐</div><h1>MyApp</h1><p>Sign in to your account</p></div>

    <!-- Lockout countdown (shown by JavaScript if locked out) -->
    <div class="lockout-box" id="lockout-box">
        <p>Account temporarily locked. Try again in:</p>
        <div class="countdown" id="countdown">0</div>
        <p style="font-size:12px; margin-top:4px; color:#9ca3af;">seconds</p>
    </div>

    <!-- Error message from PHP -->
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <!-- Login form -->
    <form id="login-form" method="POST" action="login.php">

        <div class="form-group">
            <label for="email">Email address</label>
            <input type="email" id="email" name="email"
                   placeholder="you@example.com"
                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                   required>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <div class="input-wrap">
                <input type="password" id="password" name="password"
                       placeholder="Enter your password"
                       required>
                <!-- Button to show/hide password -->
                <button type="button" class="toggle-pass" onclick="togglePassword('password', this)">
                    👁️
                </button>
            </div>
        </div>

        <button type="submit" class="btn btn-primary" id="login-btn">
            Sign In
        </button>

        <a href="register.php" class="btn btn-ghost">
            Create new account
        </a>

    </form>

    <div class="bottom-link">
        <p style="font-size:12px; color:#9ca3af; margin-top:16px;">
            Max <?= MAX_LOGIN_TRIES ?> attempts · <?= LOCKOUT_TIME ?>s lockout
        </p>
    </div>

</div>

<script>
// =============================================
// JavaScript for login page
// =============================================

// Show/hide password
function togglePassword(inputId, btn) {
    var input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
    } else {
        input.type = 'password';
        btn.textContent = '👁️';
    }
}

// --- Lockout countdown timer ---
// PHP tells us how many seconds are left through this variable
var lockoutSeconds = <?= isset($lockout_remaining) ? (int)$lockout_remaining : 0 ?>;

if (lockoutSeconds > 0) {
    startLockoutTimer(lockoutSeconds);
}

function startLockoutTimer(seconds) {
    var box      = document.getElementById('lockout-box');
    var display  = document.getElementById('countdown');
    var loginBtn = document.getElementById('login-btn');

    // Show the lockout box
    box.classList.add('show');

    // Disable the login button
    loginBtn.disabled = true;
    loginBtn.textContent = 'Locked...';

    // Save lockout end time in browser storage so it persists on page refresh
    var unlockAt = Date.now() + (seconds * 1000);
    sessionStorage.setItem('lockUntil', unlockAt);

    // Update countdown every second
    var timer = setInterval(function() {
        var remaining = Math.ceil((unlockAt - Date.now()) / 1000);

        if (remaining <= 0) {
            // Lockout is over
            clearInterval(timer);
            box.classList.remove('show');
            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign In';
            sessionStorage.removeItem('lockUntil');
        } else {
            display.textContent = remaining;
        }
    }, 500);

    // Set initial display
    display.textContent = seconds;
}

// Check if there is a saved lockout from a previous page load
var savedLockout = sessionStorage.getItem('lockUntil');
if (savedLockout) {
    var remaining = Math.ceil((parseInt(savedLockout) - Date.now()) / 1000);
    if (remaining > 0) {
        startLockoutTimer(remaining);
    } else {
        sessionStorage.removeItem('lockUntil');
    }
}
</script>

</body>
</html>
