<?php
// =============================================
// resend.php - Resend a new OTP code
// Called when user clicks "Resend code" on verify.php
// =============================================

require_once 'config.php';

// Must have completed step 1 (email/password) first
if (!isset($_SESSION['waiting_for_otp']) || !isset($_SESSION['temp_user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = $_SESSION['temp_user_id'];
$db      = connect_db();

// Delete the old OTP code
$db->prepare("DELETE FROM otp_tokens WHERE user_id = ?")->execute([$user_id]);

// Generate a new 6-digit code
$otp_code = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
$otp_hash = password_hash($otp_code, PASSWORD_BCRYPT);
$expires  = date('Y-m-d H:i:s', time() + OTP_EXPIRE);

// Save it to the database
$db->prepare("
    INSERT INTO otp_tokens (user_id, otp_code, expires_at) VALUES (?, ?, ?)
")->execute([$user_id, $otp_hash, $expires]);

// Update demo OTP in session
// ⚠️ Remove $_SESSION['demo_otp'] in production
$_SESSION['demo_otp'] = $otp_code;

// Go back to verification page
header('Location: verify.php');
exit;
?>
