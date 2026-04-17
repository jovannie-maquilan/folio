<?php
// =============================================
// config.php - Database and app settings
// =============================================

// --- Database connection info ---
// Change these to match your database
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'auth_system');
define('DB_USER', 'root');
define('DB_PASS', ''); // AWebServer default is blank

// --- Security settings ---
define('MAX_LOGIN_TRIES', 5);   // lock after 5 failed attempts
define('LOCKOUT_TIME',    300);  // lockout for 5 minutes (300 seconds)
define('OTP_EXPIRE',      300); // OTP is valid for 5 minutes (300 seconds)
define('PASSWORD_COST',   12);  // bcrypt cost parameter (10-12 recommended for security)
define('PASSWORD_PEPPER', 'Y0uR_S3cur3_P3pp3r_K3y_H3r3!@#'); // Additional salt layer

// --- Connect to the database ---
// This runs once and gives us a $pdo variable to use in every page
function connect_db() {
    static $pdo = null;

    // Only connect once (reuse the same connection)
    if ($pdo !== null) {
        return $pdo;
    }

    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS
        );
        // Show errors clearly instead of silently failing
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Return rows as arrays like $row['email'] instead of $row[0]
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        return $pdo;

    } catch (PDOException $e) {
        // Show a friendly error without revealing system details (security best practice)
        // Log the actual error for administrators to review separately
        error_log("Database connection failed: " . $e->getMessage());
        
        die("
            <div style='font-family:sans-serif; padding:30px; color:red;'>
                <h2>Service Unavailable</h2>
                <p>The application is temporarily unavailable. Please try again later.</p>
                <p style='font-size:12px; color:#666; margin-top:20px;'>Contact support if the problem persists.</p>
            </div>
        ");
    }
}

// --- Start the session ---
// Sessions let us remember who is logged in between pages
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 3600,    // session lasts 1 hour
        'path'     => '/',
        'secure'   => false,   // set true if using HTTPS
        'httponly' => true,    // prevents JavaScript from stealing the cookie
        'samesite' => 'Lax'
    ]);
    session_start();
}
?>
