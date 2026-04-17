<?php
// =============================================
// verify.php - 2FA verification page
// Step 2 of login: enter the 6-digit OTP code
// =============================================

require_once 'config.php';

// If they haven't done step 1 yet, send them back to login
if (!isset($_SESSION['waiting_for_otp']) || !isset($_SESSION['temp_user_id'])) {
    header('Location: login.php');
    exit;
}

// If already fully logged in, go to profile
if (isset($_SESSION['user_id']) && isset($_SESSION['otp_verified'])) {
    header('Location: profile.php');
    exit;
}

$error = '';
$user_id = $_SESSION['temp_user_id'];

// =============================================
// Handle OTP form when submitted
// =============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Combine the 6 separate digit inputs into one code
    $entered_otp = '';
    for ($i = 1; $i <= 6; $i++) {
        $entered_otp .= $_POST['digit' . $i] ?? '';
    }
    $entered_otp = trim($entered_otp);

    $db = connect_db();

    // Look up the latest unused OTP for this user
    $stmt = $db->prepare("
        SELECT id, otp_code
        FROM otp_tokens
        WHERE user_id = ?
          AND used = 0
        ORDER BY created_at DESC
        LIMIT 1
    ");
    $stmt->execute([$user_id]);
    $token = $stmt->fetch();

    // Compare as plain strings (trim both sides to remove hidden spaces)
    $entered_clean = trim((string)$entered_otp);
    $stored_clean  = trim((string)($token['otp_code'] ?? ''));

    if ($token && $entered_clean === $stored_clean) {

        // ✅ OTP is correct! Mark it as used so it can't be reused
        $db->prepare("UPDATE otp_tokens SET used = 1 WHERE id = ?")
           ->execute([$token['id']]);

        // Fully log in the user
        $_SESSION['user_id']     = $user_id;
        $_SESSION['otp_verified'] = true;

        // Clean up the temporary session variables
        unset($_SESSION['waiting_for_otp']);
        unset($_SESSION['temp_user_id']);
        unset($_SESSION['temp_user_name']);
        unset($_SESSION['demo_otp']);

        // Regenerate session ID to prevent session fixation attacks
        session_regenerate_id(true);

        header('Location: profile.php');
        exit;

    } else {
        $error = 'The code is wrong or has expired. Please try again.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <title>Verify - MyApp</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="auth-page">

<div class="auth-card">

    <div class="auth-logo"><div class="auth-logo-mark">🔐</div><h1>MyApp</h1><p>Two-Factor Verification</p></div>

    <h2 class="auth-title">Check your code</h2>
    <p class="auth-subtitle">
        Hello <strong><?= htmlspecialchars($_SESSION['temp_user_name'] ?? 'there') ?></strong>!
        A 6-digit code was generated for your account.
    </p>

    <!-- DEMO NOTICE: Show the OTP on screen for testing -->
    <!-- ⚠️ REMOVE THIS IN PRODUCTION — send by email/SMS instead -->
    <?php if (isset($_SESSION['demo_otp'])): ?>
        <div class="alert alert-info">
            <strong>Demo Mode:</strong> Your code is
            <strong style="font-size:18px; letter-spacing:3px;">
                <?= htmlspecialchars($_SESSION['demo_otp']) ?>
            </strong>
            <br>
            <small>(In production, this would be sent to your email/phone)</small>
        </div>
    <?php endif; ?>

    <!-- Error message -->
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <!-- OTP countdown timer -->
    <div class="otp-timer" id="otp-timer">
        Code expires in <span id="timer-seconds"><?= OTP_EXPIRE ?></span> seconds
    </div>

    <!-- OTP form: 6 separate input boxes -->
    <form id="otp-form" method="POST" action="verify.php">

        <div class="otp-wrap">
            <input class="otp-box" type="text" name="digit1" id="d1" maxlength="1" inputmode="numeric" autocomplete="off">
            <input class="otp-box" type="text" name="digit2" id="d2" maxlength="1" inputmode="numeric" autocomplete="off">
            <input class="otp-box" type="text" name="digit3" id="d3" maxlength="1" inputmode="numeric" autocomplete="off">
            <input class="otp-box" type="text" name="digit4" id="d4" maxlength="1" inputmode="numeric" autocomplete="off">
            <input class="otp-box" type="text" name="digit5" id="d5" maxlength="1" inputmode="numeric" autocomplete="off">
            <input class="otp-box" type="text" name="digit6" id="d6" maxlength="1" inputmode="numeric" autocomplete="off">
        </div>

        <button type="submit" class="btn btn-primary" id="verify-btn" disabled>
            Verify Code
        </button>

    </form>

    <!-- Resend code -->
    <form method="POST" action="resend.php" style="margin-top:10px;">
        <button type="submit" class="btn btn-ghost">
            Resend code
        </button>
    </form>

    <div class="bottom-link">
        <a href="login.php">← Back to login</a>
    </div>

</div>

<script>
// =============================================
// JavaScript for OTP page
// =============================================

var boxes = document.querySelectorAll('.otp-box');
var form  = document.getElementById('otp-form');
var btn   = document.getElementById('verify-btn');

// Auto-move to next box when a digit is typed
boxes.forEach(function(box, index) {

    box.addEventListener('input', function() {
        // Only allow numbers
        this.value = this.value.replace(/[^0-9]/, '');

        // Move to next box
        if (this.value && index < boxes.length - 1) {
            boxes[index + 1].focus();
        }

        checkAllFilled();
    });

    // Handle backspace — go back to previous box
    box.addEventListener('keydown', function(e) {
        if (e.key === 'Backspace' && !this.value && index > 0) {
            boxes[index - 1].focus();
        }
    });

    // Handle paste — fill all boxes at once
    box.addEventListener('paste', function(e) {
        e.preventDefault();
        var pasted = (e.clipboardData || window.clipboardData)
                        .getData('text')
                        .replace(/[^0-9]/g, '')
                        .slice(0, 6);

        pasted.split('').forEach(function(digit, i) {
            if (boxes[index + i]) {
                boxes[index + i].value = digit;
            }
        });

        // Focus the last filled box
        var lastFilled = Math.min(index + pasted.length - 1, boxes.length - 1);
        boxes[lastFilled].focus();
        checkAllFilled();
    });
});

// Enable submit button only when all 6 boxes are filled
function checkAllFilled() {
    var allFilled = true;
    boxes.forEach(function(box) {
        if (!box.value) allFilled = false;
    });
    btn.disabled = !allFilled;
}

// Focus first box on page load
boxes[0].focus();

// --- Countdown timer ---
var seconds  = <?= OTP_EXPIRE ?>;
var timerEl  = document.getElementById('timer-seconds');
var timerDiv = document.getElementById('otp-timer');

var interval = setInterval(function() {
    seconds--;
    timerEl.textContent = seconds;

    if (seconds <= 0) {
        clearInterval(interval);
        timerDiv.textContent  = 'Code has expired. Please request a new one.';
        timerDiv.style.color  = '#dc2626';
        btn.disabled = true;
    }
}, 1000);
</script>

</body>
</html>
