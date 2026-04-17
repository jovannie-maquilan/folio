<?php
// =============================================
// register.php - Registration page
// =============================================

require_once 'config.php';

// If already logged in, go to profile
if (isset($_SESSION['user_id']) && isset($_SESSION['otp_verified'])) {
    header('Location: profile.php');
    exit;
}

$error   = '';
$success = '';

// =============================================
// Handle registration form when submitted
// =============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Get all form values and remove extra spaces
    $first    = trim($_POST['first_name'] ?? '');
    $last     = trim($_POST['last_name']  ?? '');
    $email    = trim($_POST['email']      ?? '');
    $password = $_POST['password']        ?? '';
    $confirm  = $_POST['confirm']         ?? '';

    // --- Validate everything before saving ---
    $errors = [];

    if (empty($first) || empty($last)) {
        $errors[] = 'Please enter your first and last name.';
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }

    // Check all password requirements
    if (strlen($password) < 12) {
        $errors[] = 'Password must be at least 12 characters.';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter (A-Z).';
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter (a-z).';
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must contain at least one number (0-9).';
    }
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = 'Password must contain at least one special character (!@#$...).';
    }

    if ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    }

    // --- If no validation errors, check if email already exists ---
    if (empty($errors)) {
        $db   = connect_db();
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
        $stmt->execute([$email]);

        if ($stmt->fetch()) {
            $errors[] = 'An account with this email already exists.';
        }
    }

    // --- If still no errors, save the new user ---
    if (empty($errors)) {

        // Hash the password before storing (NEVER store plain text passwords)
        // password_hash() automatically generates a cryptographic salt using bcrypt
        // and includes it in the output hash. Additional pepper provides a second layer.
        $password_with_pepper = $password . PASSWORD_PEPPER;
        $hashed = password_hash($password_with_pepper, PASSWORD_BCRYPT, ['cost' => PASSWORD_COST]);

        $db->prepare("
            INSERT INTO users (first_name, last_name, email, password)
            VALUES (?, ?, ?, ?)
        ")->execute([$first, $last, $email, $hashed]);

        $success = "Account created! You can now sign in.";

    } else {
        // Join all errors into one message
        $error = implode('<br>', $errors);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <title>Register - MyApp</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="auth-page">

<div class="auth-card">

    <div class="auth-logo"><div class="auth-logo-mark">🔐</div><h1>MyApp</h1><p>Create your account</p></div>

    <!-- Show error or success message -->
    <?php if ($error): ?>
        <div class="alert alert-error"><?= $error ?></div>
    <?php elseif ($success): ?>
        <div class="alert alert-success">
            <?= htmlspecialchars($success) ?>
            <br><a href="login.php" style="color:#16a34a; font-weight:500;">Click here to sign in →</a>
        </div>
    <?php endif; ?>

    <!-- Only show the form if registration was not successful -->
    <?php if (!$success): ?>
    <form id="register-form" method="POST" action="register.php" novalidate>

        <!-- Name row -->
        <div class="form-row">
            <div class="form-group">
                <label for="first_name">First name</label>
                <input type="text" id="first_name" name="first_name"
                       placeholder="John"
                       value="<?= htmlspecialchars($_POST['first_name'] ?? '') ?>"
                       required>
            </div>
            <div class="form-group">
                <label for="last_name">Last name</label>
                <input type="text" id="last_name" name="last_name"
                       placeholder="Doe"
                       value="<?= htmlspecialchars($_POST['last_name'] ?? '') ?>"
                       required>
            </div>
        </div>

        <!-- Email -->
        <div class="form-group">
            <label for="email">Email address</label>
            <input type="email" id="email" name="email"
                   placeholder="you@example.com"
                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                   required>
        </div>

        <!-- Password with strength indicator -->
        <div class="form-group">
            <label for="password">Password</label>
            <div class="input-wrap">
                <input type="password" id="password" name="password"
                       placeholder="Create a strong password"
                       oninput="checkStrength(this.value)"
                       required>
                <button type="button" class="toggle-pass" onclick="togglePassword('password', this)">
                    👁️
                </button>
            </div>

            <!-- Strength bar (4 colored segments) -->
            <div class="strength-bar" id="strength-bar">
                <span id="bar1"></span>
                <span id="bar2"></span>
                <span id="bar3"></span>
                <span id="bar4"></span>
            </div>
            <div class="strength-label" id="strength-label">Enter a password</div>

            <!-- Requirements checklist -->
            <div class="requirements">
                <div class="req-item" id="req-upper">
                    <span class="dot"></span> Uppercase (A-Z)
                </div>
                <div class="req-item" id="req-lower">
                    <span class="dot"></span> Lowercase (a-z)
                </div>
                <div class="req-item" id="req-number">
                    <span class="dot"></span> Number (0-9)
                </div>
                <div class="req-item" id="req-special">
                    <span class="dot"></span> Special char
                </div>
                <div class="req-item" id="req-length">
                    <span class="dot"></span> Min. 12 chars
                </div>
            </div>
        </div>

        <!-- Confirm password -->
        <div class="form-group">
            <label for="confirm">Confirm password</label>
            <div class="input-wrap">
                <input type="password" id="confirm" name="confirm"
                       placeholder="Repeat your password"
                       oninput="checkMatch()"
                       required>
                <button type="button" class="toggle-pass" onclick="togglePassword('confirm', this)">
                    👁️
                </button>
            </div>
            <!-- Match message shown by JS -->
            <div id="match-msg" style="font-size:12px; margin-top:6px;"></div>
        </div>

        <button type="submit" class="btn btn-primary" id="register-btn">
            Create Account
        </button>

    </form>
    <?php endif; ?>

    <div class="bottom-link">
        Already have an account? <a href="login.php">Sign in</a>
    </div>

</div>

<script>
// =============================================
// JavaScript for registration page
// =============================================

// Show/hide password toggle
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

// Check if passwords match
function checkMatch() {
    var pass    = document.getElementById('password').value;
    var confirm = document.getElementById('confirm').value;
    var msg     = document.getElementById('match-msg');

    if (confirm === '') {
        msg.textContent = '';
        return;
    }

    if (pass === confirm) {
        msg.style.color = '#16a34a';
        msg.textContent = '✓ Passwords match';
    } else {
        msg.style.color = '#dc2626';
        msg.textContent = '✗ Passwords do not match';
    }
}

// Check password strength and update the visual indicator
function checkStrength(value) {
    var score = 0;

    // Check each requirement
    var hasUpper   = /[A-Z]/.test(value);
    var hasLower   = /[a-z]/.test(value);
    var hasNumber  = /[0-9]/.test(value);
    var hasSpecial = /[^A-Za-z0-9]/.test(value);
    var hasLength  = value.length >= 12;

    // Update the checklist items
    toggleReq('req-upper',   hasUpper);
    toggleReq('req-lower',   hasLower);
    toggleReq('req-number',  hasNumber);
    toggleReq('req-special', hasSpecial);
    toggleReq('req-length',  hasLength);

    // Count how many requirements are met
    if (hasUpper)   score++;
    if (hasLower)   score++;
    if (hasNumber)  score++;
    if (hasSpecial) score++;
    if (hasLength)  score++;

    // Color the strength bar segments
    var colors = ['#e5e7eb', '#e5e7eb', '#e5e7eb', '#e5e7eb'];
    var label  = 'Too weak';

    if (score >= 1) { colors[0] = '#dc2626'; label = 'Weak'; }
    if (score >= 2) { colors[1] = '#f59e0b'; label = 'Fair'; }
    if (score >= 4) { colors[2] = '#84cc16'; label = 'Good'; }
    if (score >= 5) { colors[3] = '#16a34a'; label = 'Strong ✓'; }

    // Apply colors to bar segments
    for (var i = 1; i <= 4; i++) {
        document.getElementById('bar' + i).style.background = colors[i - 1];
    }

    document.getElementById('strength-label').textContent = value ? label : 'Enter a password';

    // If score changes, also update confirm match
    checkMatch();
}

// Helper: mark a requirement as passed or failed
function toggleReq(id, passed) {
    var el = document.getElementById(id);
    if (passed) {
        el.classList.add('pass');
    } else {
        el.classList.remove('pass');
    }
}
</script>

</body>
</html>
