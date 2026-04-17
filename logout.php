<?php
// =============================================
// logout.php - Log the user out
// =============================================

require_once 'config.php';

// Destroy everything in the session
session_unset();
session_destroy();

// Redirect back to login
header('Location: login.php');
exit;
?>
