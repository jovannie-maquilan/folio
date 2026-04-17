<?php
// mailer.php - Handles sending emails via Gmail

require_once __DIR__ . '/src/PHPMailer.php';
require_once __DIR__ . '/src/SMTP.php';
require_once __DIR__ . '/src/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// --- PUT YOUR GMAIL DETAILS HERE ---
define('MAIL_FROM',     'banmaquilan@gmail.com');  // your Gmail address
define('MAIL_PASSWORD', 'qzgkuathoooxkclg');  // the 16-char App Password
define('MAIL_NAME',     'MyApp');

function send_otp_email($to_email, $to_name, $otp_code) {
    $mail = new PHPMailer(true);

    try {
        // Gmail SMTP settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = MAIL_FROM;
        $mail->Password   = MAIL_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;
// Fix for AWebServer on Android — SSL certificates are not installed
// so we tell PHP to skip certificate verification
$mail->SMTPOptions = [
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ]
];
        // Who sends and receives
        $mail->setFrom(MAIL_FROM, MAIL_NAME);
        $mail->addAddress($to_email, $to_name);

        // Email content
        $mail->isHTML(true);
        $mail->Subject = 'Your login verification code - MyApp';
        $mail->Body = "
            <div style='font-family:sans-serif; max-width:420px; margin:0 auto; padding:20px;'>
                <h2 style='color:#2563eb;'>🔐 MyApp</h2>
                <p>Hi <strong>{$to_name}</strong>,</p>
                <p>Someone tried to log in to your account. Use this code to verify:</p>

                <div style='font-size:40px; font-weight:bold; letter-spacing:10px;
                            color:#111827; background:#f3f4f6; padding:24px;
                            text-align:center; border-radius:10px; margin:24px 0;'>
                    {$otp_code}
                </div>

                <p style='color:#6b7280; font-size:13px;'>
                    ⏱ This code expires in 5 minutes.<br>
                    🚫 If you did not try to log in, ignore this email.
                </p>
                <hr style='border:none; border-top:1px solid #e5e7eb; margin:20px 0;'>
                <p style='color:#9ca3af; font-size:12px;'>MyApp Security Team</p>
            </div>
        ";

        $mail->send();
        return true;

} catch (Exception $e) {
      die('
          <div style="font-family:sans-serif; padding:20px; color:red; background:#fff;">
              <h3>Mail Error Detail:</h3>
              <p>' . $mail->ErrorInfo . '</p>
          </div>
      ');
  }
}

?>