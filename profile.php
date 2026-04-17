<?php
// ============================================================
// profile.php — Folio · Self-contained (CSS embedded)
// ============================================================
require_once 'config.php';

// SITE_URL — never use relative redirects
if (!defined('SITE_URL')) {
    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    define('SITE_URL', $proto . '://' . $_SERVER['HTTP_HOST']
        . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\'));
}

// ── Auth guard ───────────────────────────────────────────────
if (empty($_SESSION['user_id']) || empty($_SESSION['otp_verified'])) {
    header('Location: ' . SITE_URL . '/login.php'); exit;
}
$uid = (int)$_SESSION['user_id'];
$db  = connect_db();

// ── AJAX / POST handler ──────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    $act = $_POST['action'];

    // helper: safe string
    $s = fn($k) => trim($_POST[$k] ?? '');

    if ($act === 'save_profile') {
        $db->prepare("UPDATE users SET
            first_name=?,last_name=?,username=?,tagline=?,bio=?,
            gender=?,phone=?,address=?,location=?,
            website=?,github=?,linkedin=?,twitter=?
            WHERE id=?")->execute([
            $s('first_name'),$s('last_name'),$s('username'),
            $s('tagline'),$s('bio'),$s('gender'),$s('phone'),
            $s('address'),$s('location'),$s('website'),
            $s('github'),$s('linkedin'),$s('twitter'),$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    if ($act === 'upload_avatar' && isset($_FILES['avatar'])) {
        $f = $_FILES['avatar'];
        $allowed = ['image/jpeg','image/png','image/webp','image/gif'];
        if (!in_array($f['type'], $allowed))      { echo json_encode(['ok'=>false,'msg'=>'JPG/PNG/WEBP/GIF only']); exit; }
        if ($f['size'] > 2*1024*1024)             { echo json_encode(['ok'=>false,'msg'=>'Max 2 MB']); exit; }
        $ext  = strtolower(pathinfo($f['name'],PATHINFO_EXTENSION));
        $name = "avatar_{$uid}_".time().".$ext";
        $dir  = __DIR__.'/uploads/';
        if (!is_dir($dir)) mkdir($dir,0755,true);
        if (move_uploaded_file($f['tmp_name'],$dir.$name)) {
            $path = "uploads/$name";
            $db->prepare("UPDATE users SET avatar_path=? WHERE id=?")->execute([$path,$uid]);
            echo json_encode(['ok'=>true,'path'=>$path.'?v='.time()]); exit;
        }
        echo json_encode(['ok'=>false,'msg'=>'Move failed']); exit;
    }

    if ($act === 'change_password') {
        $cur=$s('current_password'); $new=$s('new_password'); $con=$s('confirm_password');
        $row=$db->prepare("SELECT password FROM users WHERE id=? LIMIT 1");
        $row->execute([$uid]); $row=$row->fetch();
        $cur_with_pepper = $cur . PASSWORD_PEPPER;
        if (!$row||!password_verify($cur_with_pepper,$row['password'])) { echo json_encode(['ok'=>false,'msg'=>'Current password wrong']); exit; }
        if ($new!==$con)   { echo json_encode(['ok'=>false,'msg'=>'Passwords do not match']); exit; }
        if (strlen($new)<12){ echo json_encode(['ok'=>false,'msg'=>'Password must be at least 12 characters']); exit; }
        if (!preg_match('/[A-Z]/',$new)){ echo json_encode(['ok'=>false,'msg'=>'Password must contain uppercase (A-Z)']); exit; }
        if (!preg_match('/[a-z]/',$new)){ echo json_encode(['ok'=>false,'msg'=>'Password must contain lowercase (a-z)']); exit; }
        if (!preg_match('/[0-9]/',$new)){ echo json_encode(['ok'=>false,'msg'=>'Password must contain number (0-9)']); exit; }
        if (!preg_match('/[^A-Za-z0-9]/',$new)){ echo json_encode(['ok'=>false,'msg'=>'Password must contain special character']); exit; }
        $new_with_pepper = $new . PASSWORD_PEPPER;
        $db->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($new_with_pepper,PASSWORD_BCRYPT,['cost'=>PASSWORD_COST]),$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    if ($act === 'toggle_2fa') {
        $st=(int)($_POST['state']??1);
        $db->prepare("UPDATE users SET twofa_enabled=? WHERE id=?")->execute([$st,$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    if ($act === 'revoke_sessions') {
        $db->prepare("DELETE FROM otp_tokens WHERE user_id=?")->execute([$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    if ($act === 'delete_account') {
        $row=$db->prepare("SELECT password FROM users WHERE id=? LIMIT 1");
        $row->execute([$uid]); $row=$row->fetch();
        if (!$row||!password_verify($s('password'),$row['password'])) { echo json_encode(['ok'=>false,'msg'=>'Incorrect password']); exit; }
        $db->prepare("DELETE FROM users WHERE id=?")->execute([$uid]);
        session_unset(); session_destroy();
        echo json_encode(['ok'=>true,'redirect'=>SITE_URL.'/register.php']); exit;
    }

    // ── Experience ─────────────────────────────────────────
    if ($act === 'add_experience') {
        $db->prepare("INSERT INTO experience(user_id,company,position,date_start,date_end,description)VALUES(?,?,?,?,?,?)")
           ->execute([$uid,$s('company'),$s('position'),$s('date_start'),$s('date_end'),$s('description')]);
        echo json_encode(['ok'=>true,'id'=>$db->lastInsertId()]); exit;
    }
    if ($act === 'edit_experience') {
        $db->prepare("UPDATE experience SET company=?,position=?,date_start=?,date_end=?,description=? WHERE id=? AND user_id=?")
           ->execute([$s('company'),$s('position'),$s('date_start'),$s('date_end'),$s('description'),(int)$_POST['id'],$uid]);
        echo json_encode(['ok'=>true]); exit;
    }
    if ($act === 'delete_experience') {
        $db->prepare("DELETE FROM experience WHERE id=? AND user_id=?")->execute([(int)$_POST['id'],$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    // ── Education ──────────────────────────────────────────
    if ($act === 'add_education') {
        $db->prepare("INSERT INTO education(user_id,institution,degree,field,year_start,year_end,description)VALUES(?,?,?,?,?,?,?)")
           ->execute([$uid,$s('institution'),$s('degree'),$s('field'),$s('year_start'),$s('year_end'),$s('description')]);
        echo json_encode(['ok'=>true,'id'=>$db->lastInsertId()]); exit;
    }
    if ($act === 'edit_education') {
        $db->prepare("UPDATE education SET institution=?,degree=?,field=?,year_start=?,year_end=?,description=? WHERE id=? AND user_id=?")
           ->execute([$s('institution'),$s('degree'),$s('field'),$s('year_start'),$s('year_end'),$s('description'),(int)$_POST['id'],$uid]);
        echo json_encode(['ok'=>true]); exit;
    }
    if ($act === 'delete_education') {
        $db->prepare("DELETE FROM education WHERE id=? AND user_id=?")->execute([(int)$_POST['id'],$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    // ── Skills ─────────────────────────────────────────────
    if ($act === 'add_skill') {
        $name=$s('name'); if(!$name){echo json_encode(['ok'=>false,'msg'=>'Name required']);exit;}
        $db->prepare("INSERT INTO skills(user_id,name,category,proficiency)VALUES(?,?,?,?)")
           ->execute([$uid,$name,$s('category')?:'General',$s('proficiency')?:'intermediate']);
        echo json_encode(['ok'=>true,'id'=>$db->lastInsertId()]); exit;
    }
    if ($act === 'delete_skill') {
        $db->prepare("DELETE FROM skills WHERE id=? AND user_id=?")->execute([(int)$_POST['id'],$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    // ── Projects ───────────────────────────────────────────
    if ($act === 'add_project') {
        $db->prepare("INSERT INTO projects(user_id,title,description,tech_stack,github_url,live_url)VALUES(?,?,?,?,?,?)")
           ->execute([$uid,$s('title'),$s('description'),$s('tech_stack'),$s('github_url'),$s('live_url')]);
        $c=$db->prepare("SELECT COUNT(*) FROM projects WHERE user_id=?"); $c->execute([$uid]);
        $db->prepare("UPDATE users SET project_count=? WHERE id=?")->execute([$c->fetchColumn(),$uid]);
        echo json_encode(['ok'=>true,'id'=>$db->lastInsertId()]); exit;
    }
    if ($act === 'edit_project') {
        $db->prepare("UPDATE projects SET title=?,description=?,tech_stack=?,github_url=?,live_url=? WHERE id=? AND user_id=?")
           ->execute([$s('title'),$s('description'),$s('tech_stack'),$s('github_url'),$s('live_url'),(int)$_POST['id'],$uid]);
        echo json_encode(['ok'=>true]); exit;
    }
    if ($act === 'delete_project') {
        $db->prepare("DELETE FROM projects WHERE id=? AND user_id=?")->execute([(int)$_POST['id'],$uid]);
        $c=$db->prepare("SELECT COUNT(*) FROM projects WHERE user_id=?"); $c->execute([$uid]);
        $db->prepare("UPDATE users SET project_count=? WHERE id=?")->execute([$c->fetchColumn(),$uid]);
        echo json_encode(['ok'=>true]); exit;
    }

    echo json_encode(['ok'=>false,'msg'=>'Unknown action']); exit;
}

// ── Page-load: increment views ───────────────────────────────
// Bug fix #1: snapshot + restore on GET session regeneration
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $snap = $_SESSION;
    @session_regenerate_id(true);
    $_SESSION = $snap;
}
$db->prepare("UPDATE users SET profile_views=profile_views+1 WHERE id=?")->execute([$uid]);

// ── Load data ────────────────────────────────────────────────
$q=fn($sql,$p=[])=>($st=$db->prepare($sql))&&$st->execute($p)?$st:null;

$user = $q("SELECT * FROM users WHERE id=? LIMIT 1",[$uid])?->fetch();
if (!$user) { session_destroy(); header('Location:'.SITE_URL.'/login.php'); exit; }

$exps  = $q("SELECT * FROM experience WHERE user_id=? ORDER BY sort_order,id DESC",[$uid])?->fetchAll()??[];
$edus  = $q("SELECT * FROM education  WHERE user_id=? ORDER BY sort_order,id DESC",[$uid])?->fetchAll()??[];
$skils = $q("SELECT * FROM skills     WHERE user_id=? ORDER BY category,sort_order,id",[$uid])?->fetchAll()??[];
$projs = $q("SELECT * FROM projects   WHERE user_id=? ORDER BY sort_order,id DESC",[$uid])?->fetchAll()??[];

$skByCat=[]; foreach($skils as $sk){ $cat=trim($sk['category'])?:'General'; $skByCat[$cat][]=$sk; }

$fullName     = trim($user['first_name'].' '.$user['last_name']);
$avatarLetter = strtoupper(substr($user['first_name']?:'?',0,1));
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0">
<title><?=htmlspecialchars($fullName)?> — Folio</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
/* ════════════════════════════════════════════
   TOKENS
════════════════════════════════════════════ */
:root{
  --bg0:#080808; --bg1:#111; --bg2:#181818; --bg3:#202020; --bg4:#2a2a2a;
  --bd:#252525; --bd2:#333;
  --t0:#f2f2f2; --t1:#aaa; --t2:#555;
  --cy:#00e5cc; --cy2:#00bfad; --cyg:rgba(0,229,204,.13); --cygg:rgba(0,229,204,.06);
  --gn:#22c55e; --rd:#ef4444; --yw:#f59e0b;
  --r:12px; --rs:8px; --rx:5px;
  --mono:'DM Mono',monospace; --head:'Syne',sans-serif;
}

/* ════════════════════════════════════════════
   RESET
════════════════════════════════════════════ */
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{font-family:var(--mono);background:var(--bg0);color:var(--t0);min-height:100vh;overflow-x:hidden;line-height:1.6}
h1,h2,h3,h4,.syne{font-family:var(--head)}
a{color:inherit;text-decoration:none}
button{cursor:pointer;font-family:var(--mono)}
input,textarea,select{font-family:var(--mono);font-size:16px;color:var(--t0);background:var(--bg2);border:1px solid var(--bd);border-radius:var(--rs);padding:11px 14px;width:100%;outline:none;transition:border-color .2s,box-shadow .2s;-webkit-appearance:none;appearance:none}
input:focus,textarea:focus,select:focus{border-color:var(--cy);box-shadow:0 0 0 3px var(--cyg)}
input::placeholder,textarea::placeholder{color:var(--t2)}
textarea{resize:vertical;min-height:80px;line-height:1.7}
select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23555' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 13px center;padding-right:36px;cursor:pointer}
select option{background:var(--bg2)}
label{display:block;font-size:11px;font-weight:500;color:var(--t2);text-transform:uppercase;letter-spacing:1px;margin-bottom:7px}
.form-group{margin-bottom:16px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.input-wrap{position:relative}
.input-wrap input{padding-right:44px}
.toggle-pass{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;font-size:16px;opacity:.4;transition:opacity .2s;padding:2px}
.toggle-pass:hover{opacity:1}

/* ════════════════════════════════════════════
   NAVBAR
════════════════════════════════════════════ */
.nav{
  position:sticky;top:0;z-index:200;height:58px;
  display:flex;align-items:center;justify-content:space-between;
  padding:0 20px;
  background:rgba(8,8,8,.94);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-bottom:1px solid var(--bd);
}
.nav-brand{font-family:var(--head);font-size:17px;font-weight:800;letter-spacing:4px;text-transform:uppercase}
.nav-brand em{color:var(--cy);font-style:normal}
.nav-right{display:flex;align-items:center;gap:8px}
.nav-pill{display:flex;align-items:center;gap:7px;padding:5px 12px;border:1px solid var(--bd);border-radius:20px;font-size:12px;color:var(--t1)}
.nav-dot{width:7px;height:7px;border-radius:50%;background:var(--gn);box-shadow:0 0 6px var(--gn);flex-shrink:0}
.btn-logout{background:none;border:1px solid var(--bd);border-radius:20px;padding:5px 13px;font-size:12px;color:var(--t2);transition:all .2s}
.btn-logout:hover{border-color:var(--rd);color:var(--rd)}
/* hamburger */
.ham{display:none;flex-direction:column;justify-content:center;gap:5px;width:34px;height:34px;background:none;border:none;padding:4px}
.ham span{display:block;width:20px;height:2px;background:var(--t0);border-radius:2px;transition:all .3s}
.ham.open span:nth-child(1){transform:translateY(7px) rotate(45deg)}
.ham.open span:nth-child(2){opacity:0;transform:scaleX(0)}
.ham.open span:nth-child(3){transform:translateY(-7px) rotate(-45deg)}
/* drawer */
.drawer{display:none;position:fixed;top:58px;left:0;right:0;background:var(--bg1);border-bottom:1px solid var(--bd);padding:14px 16px;z-index:190;animation:slideDown .22s ease}
.drawer.open{display:block}
@keyframes slideDown{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.drawer .nav-pill{width:100%;border-radius:var(--rs);justify-content:flex-start;margin-bottom:8px;pointer-events:none}
.drawer .btn-logout{width:100%;text-align:left;border-radius:var(--rs);padding:9px 13px}

/* ════════════════════════════════════════════
   HERO
════════════════════════════════════════════ */
.hero{
  background:var(--bg1);border-bottom:1px solid var(--bd);
  padding:44px 20px 0;position:relative;overflow:hidden;
}
/* subtle dot grid */
.hero::before{
  content:'';position:absolute;inset:0;
  background-image:radial-gradient(circle,var(--bd) 1px,transparent 1px);
  background-size:28px 28px;opacity:.5;pointer-events:none;
}
/* cyan glow center */
.hero::after{
  content:'';position:absolute;bottom:-80px;left:50%;transform:translateX(-50%);
  width:500px;height:200px;
  background:radial-gradient(ellipse,var(--cygg) 0%,transparent 70%);
  pointer-events:none;
}
.hero-inner{
  max-width:860px;margin:0 auto;
  display:flex;gap:32px;align-items:flex-end;
  position:relative;z-index:1;
}
/* avatar */
.av-wrap{
  flex-shrink:0;cursor:pointer;position:relative;
  width:120px;height:120px;
}
.av-wrap:hover .av-hint{opacity:1}
.av-img,.av-ph{
  width:120px;height:120px;border-radius:50%;
  border:2px solid var(--bd);
  box-shadow:0 0 0 4px var(--bg1),0 0 20px var(--cyg);
  transition:border-color .25s,box-shadow .25s;
  display:flex;align-items:center;justify-content:center;
}
.av-img{object-fit:cover}
.av-ph{background:var(--bg2);font-family:var(--head);font-size:46px;font-weight:800;color:var(--cy)}
.av-wrap:hover .av-img,
.av-wrap:hover .av-ph{
  border-color:var(--cy);
  box-shadow:0 0 0 4px var(--bg1),0 0 0 6px var(--cy),0 0 36px rgba(0,229,204,.25);
}
.av-hint{
  position:absolute;inset:0;border-radius:50%;
  background:rgba(0,0,0,.65);
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  opacity:0;transition:opacity .2s;
  font-size:11px;color:var(--cy);text-align:center;gap:3px;
}
/* hero text */
.hero-info{flex:1;padding-bottom:28px;min-width:0}
.hero-handle{font-size:12px;color:var(--cy);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.hero-name{font-family:var(--head);font-size:34px;font-weight:800;letter-spacing:-1px;line-height:1.1;margin-bottom:8px;word-break:break-word}
.hero-tagline{font-size:13px;color:var(--t1);margin-bottom:16px;line-height:1.55}
.hero-links{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.hero-link{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t2);transition:color .2s;word-break:break-all}
.hero-link:hover{color:var(--cy)}
.hero-link svg{width:13px;height:13px;flex-shrink:0}
/* stats */
.hero-stats{display:flex;gap:24px;margin-bottom:22px}
.stat-num{font-family:var(--head);font-size:26px;font-weight:800;color:var(--t0);line-height:1}
.stat-lbl{font-size:10px;color:var(--t2);text-transform:uppercase;letter-spacing:.8px;margin-top:3px}
/* edit btn */
.btn-edit{
  display:inline-flex;align-items:center;gap:7px;
  padding:9px 20px;border-radius:22px;border:none;
  background:var(--cy);color:#000;
  font-family:var(--mono);font-size:12px;font-weight:500;
  text-transform:uppercase;letter-spacing:.5px;
  transition:all .2s;box-shadow:0 0 18px var(--cyg);
}
.btn-edit:hover{background:var(--cy2);box-shadow:0 0 28px rgba(0,229,204,.3);transform:translateY(-1px)}

/* ════════════════════════════════════════════
   TABS
════════════════════════════════════════════ */
.tabs-bar{
  background:var(--bg1);border-bottom:1px solid var(--bd);
  position:sticky;top:58px;z-index:100;
}
.tabs-scroll{
  max-width:860px;margin:0 auto;
  display:flex;overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch;
}
.tabs-scroll::-webkit-scrollbar{display:none}
.tab-btn{
  padding:15px 18px;background:none;border:none;border-bottom:2px solid transparent;
  font-family:var(--mono);font-size:12px;color:var(--t2);
  white-space:nowrap;text-transform:uppercase;letter-spacing:1px;
  margin-bottom:-1px;transition:color .2s,border-color .2s;
}
.tab-btn:hover{color:var(--t1)}
.tab-btn.active{color:var(--cy);border-bottom-color:var(--cy)}

/* ════════════════════════════════════════════
   CONTENT WRAPPER
════════════════════════════════════════════ */
.content{max-width:860px;margin:0 auto;padding:28px 20px 72px}
.tab-pane{display:none}
.tab-pane.active{display:block;animation:fadeIn .18s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

/* section head */
.sec-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;padding-bottom:11px;border-bottom:1px solid var(--bd)}
.sec-title{font-family:var(--head);font-size:11px;font-weight:700;letter-spacing:2.5px;text-transform:uppercase;color:var(--t2)}

/* ════════════════════════════════════════════
   BUTTONS (shared)
════════════════════════════════════════════ */
.btn{display:block;width:100%;padding:12px 18px;border:none;border-radius:var(--rs);font-family:var(--mono);font-size:13px;text-align:center;text-transform:uppercase;letter-spacing:.5px;transition:all .2s;margin-top:6px;text-decoration:none}
.btn-primary{background:var(--cy);color:#000;box-shadow:0 0 16px var(--cyg)}
.btn-primary:hover{background:var(--cy2);transform:translateY(-1px);box-shadow:0 0 24px rgba(0,229,204,.25)}
.btn-ghost{background:transparent;color:var(--t1);border:1px solid var(--bd)}
.btn-ghost:hover{border-color:var(--bd2);background:var(--bg2)}
.btn-danger{background:rgba(239,68,68,.08);color:var(--rd);border:1px solid rgba(239,68,68,.2)}
.btn-danger:hover{background:rgba(239,68,68,.15);border-color:var(--rd)}
.btn-sm{display:inline-flex;align-items:center;gap:6px;width:auto;padding:7px 14px;font-size:11px;margin-top:0;border-radius:20px}
.btn-xs{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;padding:0;font-size:14px;border-radius:var(--rx);background:var(--bg3);border:1px solid var(--bd);color:var(--t1);margin-top:0;transition:all .2s}
.btn-xs:hover{border-color:var(--cy);color:var(--cy)}
.btn-xs.del:hover{border-color:var(--rd);color:var(--rd)}

/* ════════════════════════════════════════════
   ABOUT TAB
════════════════════════════════════════════ */
.bio-card{background:var(--bg1);border:1px solid var(--bd);border-radius:var(--r);padding:20px 22px;margin-bottom:22px;font-size:13px;color:var(--t1);line-height:1.85;white-space:pre-wrap}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--bd);border:1px solid var(--bd);border-radius:var(--r);overflow:hidden}
.info-cell{background:var(--bg1);padding:14px 18px}
.info-cell.full{grid-column:1/-1}
.cell-lbl{font-size:10px;font-weight:600;color:var(--t2);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.cell-val{font-size:13px;color:var(--t0);word-break:break-word;line-height:1.5}

/* ════════════════════════════════════════════
   TIMELINE  (Experience + Education)
════════════════════════════════════════════ */
.timeline{position:relative;padding-left:2px}
.timeline::before{content:'';position:absolute;left:17px;top:14px;bottom:14px;width:1px;background:linear-gradient(to bottom,transparent,var(--bd) 8%,var(--bd) 92%,transparent)}
.tl-item{display:flex;gap:20px;margin-bottom:18px;position:relative}
.tl-dot{width:10px;height:10px;border-radius:50%;border:2px solid var(--cy);background:var(--bg0);flex-shrink:0;margin-top:16px;position:relative;z-index:1;box-shadow:0 0 8px var(--cyg)}
.tl-card{flex:1;background:var(--bg1);border:1px solid var(--bd);border-radius:var(--r);padding:16px 18px;transition:border-color .2s;min-width:0}
.tl-card:hover{border-color:var(--bd2)}
.tl-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}
.tl-actions{display:flex;gap:5px;flex-shrink:0}
.tl-title{font-size:15px;font-weight:700;color:var(--t0);line-height:1.3}
.tl-sub{font-size:12px;color:var(--cy);margin:3px 0;font-family:var(--mono)}
.tl-dates{font-size:11px;color:var(--t2);letter-spacing:.4px}
.tl-desc{font-size:13px;color:var(--t1);line-height:1.75;margin-top:10px;padding-top:10px;border-top:1px solid var(--bd)}

/* ════════════════════════════════════════════
   SKILLS TAB
════════════════════════════════════════════ */
.skill-legend{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:22px}
.leg-item{display:flex;align-items:center;gap:7px;font-size:11px;color:var(--t2)}
.leg-dot{width:8px;height:8px;border-radius:50%}
.leg-dot.b{background:#3b82f6} .leg-dot.i{background:#8b5cf6} .leg-dot.a{background:#f59e0b} .leg-dot.e{background:var(--cy);box-shadow:0 0 6px var(--cyg)}
.skill-group{margin-bottom:26px}
.skill-cat{font-size:10px;font-weight:600;letter-spacing:1.5px;text-transform:uppercase;color:var(--t2);margin-bottom:11px}
.skill-chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{display:inline-flex;align-items:center;gap:8px;padding:7px 13px;border-radius:20px;font-size:12px;border:1px solid}
.chip.b{background:rgba(59,130,246,.07);border-color:rgba(59,130,246,.3);color:#60a5fa}
.chip.i{background:rgba(139,92,246,.07);border-color:rgba(139,92,246,.3);color:#a78bfa}
.chip.a{background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.3);color:#fbbf24}
.chip.e{background:var(--cygg);border-color:rgba(0,229,204,.3);color:var(--cy)}
.chip-del{background:none;border:none;font-size:16px;line-height:1;opacity:.4;color:inherit;padding:0;transition:opacity .15s}
.chip-del:hover{opacity:1}

/* ════════════════════════════════════════════
   PROJECTS TAB
════════════════════════════════════════════ */
.proj-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.proj-card{background:var(--bg1);border:1px solid var(--bd);border-radius:var(--r);padding:20px;position:relative;overflow:hidden;display:flex;flex-direction:column;transition:border-color .2s,transform .2s}
.proj-card:hover{border-color:var(--bd2);transform:translateY(-2px)}
.proj-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--cy),transparent);opacity:0;transition:opacity .2s}
.proj-card:hover::before{opacity:1}
/* desktop overlay — hover only */
.proj-overlay{position:absolute;inset:0;background:rgba(5,5,5,.87);border-radius:var(--r);display:flex;align-items:center;justify-content:center;gap:10px;opacity:0;transition:opacity .2s}
.proj-card:hover .proj-overlay{opacity:1}
.proj-title{font-family:var(--head);font-size:15px;font-weight:700;color:var(--t0);margin-bottom:8px}
.proj-desc{font-size:12px;color:var(--t1);line-height:1.75;margin-bottom:12px;flex:1}
.tech-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.tech-badge{font-size:11px;padding:3px 9px;border-radius:4px;background:var(--bg3);color:var(--t1);border:1px solid var(--bd)}
.proj-links{display:flex;gap:12px}
.proj-link{font-size:12px;color:var(--t2);display:flex;align-items:center;gap:5px;transition:color .2s}
.proj-link:hover{color:var(--cy)}

/* ════════════════════════════════════════════
   SECURITY TAB
════════════════════════════════════════════ */
.sec-card{background:var(--bg1);border:1px solid var(--bd);border-radius:var(--r);padding:20px 22px;margin-bottom:14px}
.sec-card-title{font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:2.5px;text-transform:uppercase;color:var(--t2);padding-bottom:12px;margin-bottom:18px;border-bottom:1px solid var(--bd)}
.twofa-row{display:flex;align-items:center;justify-content:space-between;gap:16px}
.twofa-info h4{font-size:14px;font-weight:600;color:var(--t0);margin-bottom:4px}
.twofa-info p{font-size:12px;color:var(--t2);line-height:1.5}
.twofa-status{font-size:11px;margin-top:6px;letter-spacing:.4px}
.twofa-status.on{color:var(--gn)} .twofa-status.off{color:var(--t2)}
/* toggle switch */
.tog{position:relative;width:50px;height:28px;flex-shrink:0;cursor:pointer}
.tog input{display:none}
.tog-track{position:absolute;inset:0;background:var(--bg4);border:1px solid var(--bd2);border-radius:14px;transition:all .3s}
.tog-thumb{position:absolute;top:4px;left:4px;width:20px;height:20px;border-radius:50%;background:var(--t2);box-shadow:0 1px 4px rgba(0,0,0,.5);transition:all .32s cubic-bezier(.34,1.56,.64,1)}
.tog input:checked~.tog-track{background:rgba(0,229,204,.12);border-color:var(--cy)}
.tog input:checked~.tog-thumb{left:26px;background:var(--cy);box-shadow:0 0 10px var(--cyg)}
/* strength bar */
.str-bar{display:flex;gap:4px;margin-top:9px}
.str-bar span{flex:1;height:3px;border-radius:2px;background:var(--bd2);transition:background .3s}
.str-lbl{font-size:11px;color:var(--t2);margin-top:5px;letter-spacing:.3px}
/* danger zone */
.danger{background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.18);border-radius:var(--r);padding:20px 22px;margin-top:8px}
.danger-title{font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--rd);margin-bottom:8px}
.danger p{font-size:12px;color:var(--t2);margin-bottom:14px;line-height:1.65}

/* ════════════════════════════════════════════
   EMPTY STATE
════════════════════════════════════════════ */
.empty{text-align:center;padding:54px 20px;color:var(--t2)}
.empty-ico{font-size:34px;margin-bottom:12px;opacity:.3}
.empty p{font-size:13px}

/* ════════════════════════════════════════════
   MODALS
════════════════════════════════════════════ */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:500;display:flex;align-items:center;justify-content:center;padding:20px;opacity:0;pointer-events:none;transition:opacity .22s}
.overlay.open{opacity:1;pointer-events:all}
.modal{background:var(--bg1);border:1px solid var(--bd);border-radius:var(--r);width:100%;max-width:520px;max-height:90dvh;overflow-y:auto;transform:translateY(22px) scale(.97);transition:transform .26s cubic-bezier(.16,1,.3,1)}
.overlay.open .modal{transform:translateY(0) scale(1)}
.modal-head{padding:18px 22px 14px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--bg1);z-index:1}
.modal-title{font-family:var(--head);font-size:16px;font-weight:700}
.modal-close{background:none;border:1px solid var(--bd);border-radius:var(--rx);width:30px;height:30px;display:flex;align-items:center;justify-content:center;font-size:17px;color:var(--t1);transition:all .15s}
.modal-close:hover{border-color:var(--rd);color:var(--rd)}
.modal-body{padding:20px 22px}
.modal-foot{padding:14px 22px;border-top:1px solid var(--bd);display:flex;gap:10px;justify-content:flex-end}
.modal-foot .btn{width:auto;margin:0;padding:9px 20px}
/* danger inside modal */
.modal-danger{margin-top:22px;padding-top:20px;border-top:1px solid rgba(239,68,68,.2)}
.modal-danger h4{font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--rd);margin-bottom:8px}
.modal-danger p{font-size:12px;color:var(--t2);margin-bottom:13px;line-height:1.65}
/* alert */
.alert{padding:11px 14px;border-radius:var(--rs);font-size:12px;line-height:1.55;margin-bottom:16px}
.alert-error{background:rgba(239,68,68,.08);color:var(--rd);border:1px solid rgba(239,68,68,.2)}

/* ════════════════════════════════════════════
   TOASTS
════════════════════════════════════════════ */
#toasts{position:fixed;bottom:22px;right:22px;display:flex;flex-direction:column;gap:8px;z-index:9999}
.toast{background:var(--bg2);border:1px solid var(--bd2);border-radius:var(--rs);padding:11px 16px;font-size:12px;color:var(--t0);display:flex;align-items:center;gap:9px;min-width:230px;max-width:320px;box-shadow:0 8px 24px rgba(0,0,0,.5);animation:tIn .25s cubic-bezier(.16,1,.3,1) both}
.toast::before{font-weight:700;flex-shrink:0}
.toast.ok::before{content:'✓';color:var(--gn)} .toast.err::before{content:'✕';color:var(--rd)} .toast.info::before{content:'·';color:var(--cy);font-size:20px}
.toast.out{animation:tOut .2s ease forwards}
@keyframes tIn{from{opacity:0;transform:translateX(14px)}to{opacity:1;transform:translateX(0)}}
@keyframes tOut{to{opacity:0;transform:translateX(14px)}}

/* ════════════════════════════════════════════
   RESPONSIVE — tablet ≤768px
════════════════════════════════════════════ */
@media(max-width:768px){
  .nav-right{display:none} .ham{display:flex}
  .hero{padding:28px 16px 0}
  .hero-inner{flex-direction:column;align-items:center;text-align:center;gap:18px}
  .hero-links{justify-content:center}
  .hero-stats{justify-content:center;gap:20px}
  .btn-edit{align-self:center}
  .hero-name{font-size:26px}
  .info-grid{grid-template-columns:1fr}
  .proj-grid{grid-template-columns:1fr}
  /* mobile projects: overlay always visible, stacked below card content */
  .proj-overlay{
    opacity:1!important;position:static;
    background:transparent;
    border-radius:0 0 var(--r) var(--r);
    padding:0;margin-top:12px;
    justify-content:flex-start;gap:8px;
  }
  .proj-card{transform:none!important}
  /* modal → bottom sheet */
  .overlay{align-items:flex-end;padding:0}
  .modal{max-width:100%;border-radius:var(--r) var(--r) 0 0;max-height:92dvh;transform:translateY(100%)}
  .overlay.open .modal{transform:translateY(0)}
  /* toast full-width bottom */
  #toasts{bottom:0;right:0;left:0;gap:0}
  .toast{min-width:0;max-width:100%;border-radius:0;border-left:none;border-right:none;border-bottom:none}
}
@media(max-width:480px){
  .tab-btn{font-size:11px;padding:13px 13px;letter-spacing:.3px}
  .hero-name{font-size:22px}
  .form-row{grid-template-columns:1fr}
  .av-img,.av-ph{width:90px;height:90px}
  .av-wrap{width:90px;height:90px}
  .av-ph{font-size:34px}
}
</style>
</head>
<body>

<!-- ══ NAVBAR ════════════════════════════════════════ -->
<nav class="nav">
  <div class="nav-brand">F<em>o</em>lio</div>
  <div class="nav-right">
    <div class="nav-pill"><span class="nav-dot"></span><?=htmlspecialchars($user['email'])?></div>
    <form method="POST" action="logout.php" style="margin:0">
      <button class="btn-logout">Log out</button>
    </form>
  </div>
  <button class="ham" id="ham"><span></span><span></span><span></span></button>
</nav>
<div class="drawer" id="drawer">
  <div class="nav-pill"><span class="nav-dot"></span><?=htmlspecialchars($user['email'])?></div>
  <form method="POST" action="logout.php">
    <button class="btn-logout">Log out</button>
  </form>
</div>

<!-- ══ HERO ══════════════════════════════════════════ -->
<section class="hero">
  <div class="hero-inner">

    <!-- avatar -->
    <div class="av-wrap" onclick="document.getElementById('av-in').click()" title="Change photo">
      <?php if(!empty($user['avatar_path'])&&file_exists(__DIR__.'/'.$user['avatar_path'])): ?>
        <img class="av-img" id="av-img" src="<?=htmlspecialchars($user['avatar_path'])?>?v=<?=time()?>" alt="Avatar">
      <?php else: ?>
        <div class="av-ph" id="av-ph"><?=$avatarLetter?></div>
      <?php endif; ?>
      <div class="av-hint">📷<br>Upload</div>
    </div>
    <input type="file" id="av-in" accept="image/jpeg,image/png,image/webp,image/gif" style="display:none">

    <div class="hero-info">
      <?php if(!empty($user['username'])): ?>
      <div class="hero-handle">@<?=htmlspecialchars($user['username'])?></div>
      <?php endif; ?>
      <h1 class="hero-name"><?=htmlspecialchars($fullName)?></h1>
      <p class="hero-tagline"><?=!empty($user['tagline'])?htmlspecialchars($user['tagline']):'<span style="color:var(--t2);font-size:12px;">No tagline yet — click Edit Profile</span>'?></p>

      <!-- meta links -->
      <div class="hero-links">
        <?php if(!empty($user['location'])): ?>
        <span class="hero-link">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/></svg>
          <?=htmlspecialchars($user['location'])?>
        </span>
        <?php endif; ?>
        <?php if(!empty($user['website'])): ?>
        <a class="hero-link" href="<?=htmlspecialchars($user['website'])?>" target="_blank" rel="noopener">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          <?=htmlspecialchars(parse_url($user['website'],PHP_URL_HOST)?:$user['website'])?>
        </a>
        <?php endif; ?>
        <?php if(!empty($user['github'])): ?>
        <a class="hero-link" href="<?=htmlspecialchars($user['github'])?>" target="_blank" rel="noopener">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.87 8.17 6.84 9.5.5.08.66-.23.66-.5v-1.69c-2.77.6-3.36-1.34-3.36-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.87 1.52 2.34 1.07 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.92 0-1.11.38-2 1.03-2.71-.1-.25-.45-1.29.1-2.64 0 0 .84-.27 2.75 1.02.79-.22 1.65-.33 2.5-.33.85 0 1.71.11 2.5.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.35.2 2.39.1 2.64.65.71 1.03 1.6 1.03 2.71 0 3.82-2.34 4.66-4.57 4.91.36.31.69.92.69 1.85V21c0 .27.16.59.67.5C19.14 20.16 22 16.42 22 12A10 10 0 0 0 12 2z"/></svg>
          GitHub
        </a>
        <?php endif; ?>
        <?php if(!empty($user['linkedin'])): ?>
        <a class="hero-link" href="<?=htmlspecialchars($user['linkedin'])?>" target="_blank" rel="noopener">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6zM2 9h4v12H2z"/><circle cx="4" cy="4" r="2"/></svg>
          LinkedIn
        </a>
        <?php endif; ?>
      </div>

      <!-- stats -->
      <div class="hero-stats">
        <div><div class="stat-num"><?=number_format($user['profile_views'])?></div><div class="stat-lbl">Views</div></div>
        <div><div class="stat-num"><?=count($exps)?></div><div class="stat-lbl">Experience</div></div>
        <div><div class="stat-num"><?=count($projs)?></div><div class="stat-lbl">Projects</div></div>
      </div>

      <button class="btn-edit" onclick="openM('m-profile')">✏️ Edit Profile</button>
    </div>
  </div>
</section>

<!-- ══ TABS ══════════════════════════════════════════ -->
<div class="tabs-bar">
  <div class="tabs-scroll" id="tabs">
    <button class="tab-btn active" data-tab="about">About</button>
    <button class="tab-btn" data-tab="exp">Experience</button>
    <button class="tab-btn" data-tab="edu">Education</button>
    <button class="tab-btn" data-tab="skills">Skills</button>
    <button class="tab-btn" data-tab="projects">Projects</button>
    <button class="tab-btn" data-tab="security">Security</button>
  </div>
</div>

<!-- ══ TAB CONTENT ══════════════════════════════════ -->
<div class="content">

  <!-- ABOUT -->
  <div class="tab-pane active" id="tab-about">
    <div class="bio-card"><?=!empty($user['bio'])?htmlspecialchars($user['bio']):'No bio yet. Click Edit Profile to add one.'?></div>
    <div class="sec-head"><div class="sec-title">Personal Info</div></div>
    <div class="info-grid">
      <div class="info-cell"><div class="cell-lbl">Full Name</div><div class="cell-val"><?=htmlspecialchars($fullName)?></div></div>
      <div class="info-cell"><div class="cell-lbl">Email</div><div class="cell-val"><?=htmlspecialchars($user['email'])?></div></div>
      <div class="info-cell"><div class="cell-lbl">Gender</div><div class="cell-val"><?=htmlspecialchars($user['gender']?:'—')?></div></div>
      <div class="info-cell"><div class="cell-lbl">Phone</div><div class="cell-val"><?=htmlspecialchars($user['phone']?:'—')?></div></div>
      <div class="info-cell full"><div class="cell-lbl">Address</div><div class="cell-val"><?=$user['address']?nl2br(htmlspecialchars($user['address'])):'—'?></div></div>
    </div>
  </div>

  <!-- EXPERIENCE -->
  <div class="tab-pane" id="tab-exp">
    <div class="sec-head">
      <div class="sec-title">Work Experience</div>
      <button class="btn btn-primary btn-sm" onclick="openExpModal()">+ Add</button>
    </div>
    <div class="timeline" id="exp-list">
      <?php if(empty($exps)): ?><div class="empty"><div class="empty-ico">💼</div><p>No experience added yet</p></div>
      <?php else: foreach($exps as $e): ?>
      <div class="tl-item" id="ex<?=$e['id']?>">
        <div class="tl-dot"></div>
        <div class="tl-card">
          <div class="tl-top">
            <div>
              <div class="tl-title"><?=htmlspecialchars($e['position'])?></div>
              <div class="tl-sub"><?=htmlspecialchars($e['company'])?></div>
              <div class="tl-dates"><?=htmlspecialchars($e['date_start'])?> — <?=htmlspecialchars($e['date_end']?:'Present')?></div>
            </div>
            <div class="tl-actions">
              <button class="btn-xs" onclick='openExpModal(<?=htmlspecialchars(json_encode($e),ENT_QUOTES)?>)'>✏️</button>
              <button class="btn-xs del" onclick="del('experience',<?=$e['id']?>,'ex<?=$e['id']?>')">🗑</button>
            </div>
          </div>
          <?php if(!empty($e['description'])): ?><div class="tl-desc"><?=nl2br(htmlspecialchars($e['description']))?></div><?php endif; ?>
        </div>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>

  <!-- EDUCATION -->
  <div class="tab-pane" id="tab-edu">
    <div class="sec-head">
      <div class="sec-title">Education</div>
      <button class="btn btn-primary btn-sm" onclick="openEduModal()">+ Add</button>
    </div>
    <div class="timeline" id="edu-list">
      <?php if(empty($edus)): ?><div class="empty"><div class="empty-ico">🎓</div><p>No education added yet</p></div>
      <?php else: foreach($edus as $e): ?>
      <div class="tl-item" id="ed<?=$e['id']?>">
        <div class="tl-dot"></div>
        <div class="tl-card">
          <div class="tl-top">
            <div>
              <div class="tl-title"><?=htmlspecialchars($e['degree'])?><?=!empty($e['field'])?' — '.htmlspecialchars($e['field']):''?></div>
              <div class="tl-sub"><?=htmlspecialchars($e['institution'])?></div>
              <div class="tl-dates"><?=htmlspecialchars($e['year_start'])?> — <?=htmlspecialchars($e['year_end']?:'Present')?></div>
            </div>
            <div class="tl-actions">
              <button class="btn-xs" onclick='openEduModal(<?=htmlspecialchars(json_encode($e),ENT_QUOTES)?>)'>✏️</button>
              <button class="btn-xs del" onclick="del('education',<?=$e['id']?>,'ed<?=$e['id']?>')">🗑</button>
            </div>
          </div>
          <?php if(!empty($e['description'])): ?><div class="tl-desc"><?=nl2br(htmlspecialchars($e['description']))?></div><?php endif; ?>
        </div>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>

  <!-- SKILLS -->
  <div class="tab-pane" id="tab-skills">
    <div class="sec-head">
      <div class="sec-title">Skills</div>
      <button class="btn btn-primary btn-sm" onclick="openM('m-skill')">+ Add</button>
    </div>
    <div class="skill-legend">
      <div class="leg-item"><div class="leg-dot b"></div>Beginner</div>
      <div class="leg-item"><div class="leg-dot i"></div>Intermediate</div>
      <div class="leg-item"><div class="leg-dot a"></div>Advanced</div>
      <div class="leg-item"><div class="leg-dot e"></div>Expert</div>
    </div>
    <div id="skill-wrap">
      <?php if(empty($skByCat)): ?><div class="empty"><div class="empty-ico">⚡</div><p>No skills added yet</p></div>
      <?php else: foreach($skByCat as $cat=>$items): ?>
      <div class="skill-group">
        <div class="skill-cat"><?=htmlspecialchars($cat)?></div>
        <div class="skill-chips">
          <?php foreach($items as $sk):
            $cl=['beginner'=>'b','intermediate'=>'i','advanced'=>'a','expert'=>'e'][$sk['proficiency']]??'i';
          ?>
          <span class="chip <?=$cl?>" id="sk<?=$sk['id']?>">
            <?=htmlspecialchars($sk['name'])?>
            <button class="chip-del" onclick="delSkill(<?=$sk['id']?>)">×</button>
          </span>
          <?php endforeach; ?>
        </div>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>

  <!-- PROJECTS -->
  <div class="tab-pane" id="tab-projects">
    <div class="sec-head">
      <div class="sec-title">Projects</div>
      <button class="btn btn-primary btn-sm" onclick="openProjModal()">+ Add</button>
    </div>
    <div class="proj-grid" id="proj-grid">
      <?php if(empty($projs)): ?><div class="empty" style="grid-column:1/-1"><div class="empty-ico">🚀</div><p>No projects yet</p></div>
      <?php else: foreach($projs as $p):
        $tech=array_filter(array_map('trim',explode(',',$p['tech_stack']??'')));
      ?>
      <div class="proj-card" id="pr<?=$p['id']?>">
        <div class="proj-overlay">
          <button class="btn btn-primary btn-sm" onclick='openProjModal(<?=htmlspecialchars(json_encode($p),ENT_QUOTES)?>)'>✏️ Edit</button>
          <button class="btn btn-danger btn-sm" onclick="del('project',<?=$p['id']?>,'pr<?=$p['id']?>')">🗑 Delete</button>
        </div>
        <div class="proj-title"><?=htmlspecialchars($p['title'])?></div>
        <div class="proj-desc"><?=nl2br(htmlspecialchars($p['description']))?></div>
        <?php if(!empty($tech)): ?><div class="tech-row"><?php foreach($tech as $t): ?><span class="tech-badge"><?=htmlspecialchars($t)?></span><?php endforeach; ?></div><?php endif; ?>
        <div class="proj-links">
          <?php if(!empty($p['github_url'])): ?><a class="proj-link" href="<?=htmlspecialchars($p['github_url'])?>" target="_blank" rel="noopener">⌥ GitHub</a><?php endif; ?>
          <?php if(!empty($p['live_url'])): ?><a class="proj-link" href="<?=htmlspecialchars($p['live_url'])?>" target="_blank" rel="noopener">🌐 Live</a><?php endif; ?>
        </div>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>

  <!-- SECURITY -->
  <div class="tab-pane" id="tab-security">

    <div class="sec-card">
      <div class="sec-card-title">Two-Factor Authentication</div>
      <div class="twofa-row">
        <div class="twofa-info">
          <h4>Login verification code</h4>
          <p>A 6-digit code is emailed on every sign-in</p>
          <div class="twofa-status <?=$user['twofa_enabled']?'on':'off'?>" id="twofa-lbl"><?=$user['twofa_enabled']?'● Enabled':'○ Disabled'?></div>
        </div>
        <label class="tog">
          <input type="checkbox" id="twofa-tog" <?=$user['twofa_enabled']?'checked':''?>>
          <div class="tog-track"></div>
          <div class="tog-thumb"></div>
        </label>
      </div>
    </div>

    <div class="sec-card">
      <div class="sec-card-title">Trusted Devices</div>
      <p style="font-size:13px;color:var(--t1);margin-bottom:14px;line-height:1.65">Revoke all OTP tokens and active sessions tied to your account.</p>
      <button class="btn btn-ghost btn-sm" onclick="revokeAll()">🔒 Revoke All Devices</button>
    </div>

    <div class="sec-card">
      <div class="sec-card-title">Change Password</div>
      <div class="form-group">
        <label>Current password</label>
        <div class="input-wrap"><input type="password" id="cp-cur" placeholder="Current password"><button type="button" class="toggle-pass" onclick="togPass('cp-cur',this)">👁</button></div>
      </div>
      <div class="form-group">
        <label>New password</label>
        <div class="input-wrap"><input type="password" id="cp-new" placeholder="At least 8 characters" oninput="strBar(this.value)"><button type="button" class="toggle-pass" onclick="togPass('cp-new',this)">👁</button></div>
        <div class="str-bar"><span id="sb1"></span><span id="sb2"></span><span id="sb3"></span><span id="sb4"></span></div>
        <div class="str-lbl" id="sb-lbl">Enter a password</div>
      </div>
      <div class="form-group">
        <label>Confirm new password</label>
        <div class="input-wrap"><input type="password" id="cp-con" placeholder="Repeat new password"><button type="button" class="toggle-pass" onclick="togPass('cp-con',this)">👁</button></div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="changePw()" style="margin-top:8px">Update Password</button>
    </div>

    <div class="danger">
      <div class="danger-title">⚠ Danger Zone</div>
      <p>Permanently deletes your account and all associated data. This cannot be undone.</p>
      <button class="btn btn-danger btn-sm" onclick="openM('m-delete')">Delete My Account</button>
    </div>

  </div>
</div><!-- /content -->

<!-- ══ MODALS ════════════════════════════════════════ -->

<!-- Edit Profile -->
<div class="overlay" id="m-profile">
<div class="modal">
  <div class="modal-head"><div class="modal-title">Edit Profile</div><button class="modal-close" onclick="closeM('m-profile')">✕</button></div>
  <div class="modal-body">
    <div class="form-row">
      <div class="form-group"><label>First name</label><input type="text" id="ep-fn" value="<?=htmlspecialchars($user['first_name'])?>"></div>
      <div class="form-group"><label>Last name</label><input type="text" id="ep-ln" value="<?=htmlspecialchars($user['last_name'])?>"></div>
    </div>
    <div class="form-group"><label>Username</label><input type="text" id="ep-un" placeholder="@handle" value="<?=htmlspecialchars($user['username']??'')?>"></div>
    <div class="form-group"><label>Tagline</label><input type="text" id="ep-tg" placeholder="e.g. Full-stack Developer · Open to work" value="<?=htmlspecialchars($user['tagline']??'')?>"></div>
    <div class="form-group"><label>Bio</label><textarea id="ep-bio" rows="4" placeholder="Tell people about yourself..."><?=htmlspecialchars($user['bio']??'')?></textarea></div>
    <div class="form-row">
      <div class="form-group"><label>Gender</label>
        <select id="ep-gender">
          <option value="">— Select —</option>
          <?php foreach(['Male','Female','Non-binary','Prefer not to say'] as $g): ?>
          <option <?=($user['gender']??'')===$g?'selected':''?>><?=$g?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="form-group"><label>Phone</label><input type="tel" id="ep-ph" placeholder="+63 900 000 0000" value="<?=htmlspecialchars($user['phone']??'')?>"></div>
    </div>
    <div class="form-group"><label>Address</label><textarea id="ep-addr" rows="2" placeholder="Street, City, Country"><?=htmlspecialchars($user['address']??'')?></textarea></div>
    <div class="form-group"><label>Location (public)</label><input type="text" id="ep-loc" placeholder="e.g. Cebu, Philippines" value="<?=htmlspecialchars($user['location']??'')?>"></div>
    <div class="form-group"><label>Website</label><input type="url" id="ep-web" placeholder="https://yoursite.com" value="<?=htmlspecialchars($user['website']??'')?>"></div>
    <div class="form-row">
      <div class="form-group"><label>GitHub URL</label><input type="url" id="ep-gh" placeholder="https://github.com/you" value="<?=htmlspecialchars($user['github']??'')?>"></div>
      <div class="form-group"><label>LinkedIn URL</label><input type="url" id="ep-li" placeholder="https://linkedin.com/in/you" value="<?=htmlspecialchars($user['linkedin']??'')?>"></div>
    </div>
    <div class="form-group"><label>Twitter / X URL</label><input type="url" id="ep-tw" placeholder="https://twitter.com/you" value="<?=htmlspecialchars($user['twitter']??'')?>"></div>
    <div class="modal-danger">
      <h4>⚠ Danger Zone</h4>
      <p>Permanently delete your account and all data.</p>
      <button class="btn btn-danger btn-sm" onclick="closeM('m-profile');openM('m-delete')">Delete Account</button>
    </div>
  </div>
  <div class="modal-foot">
    <button class="btn btn-ghost" onclick="closeM('m-profile')">Cancel</button>
    <button class="btn btn-primary" onclick="saveProfile()">Save Changes</button>
  </div>
</div>
</div>

<!-- Experience -->
<div class="overlay" id="m-exp">
<div class="modal">
  <div class="modal-head"><div class="modal-title" id="exp-mtitle">Add Experience</div><button class="modal-close" onclick="closeM('m-exp')">✕</button></div>
  <div class="modal-body">
    <input type="hidden" id="exp-id">
    <div class="form-group"><label>Position / Role</label><input type="text" id="exp-pos" placeholder="e.g. Frontend Developer"></div>
    <div class="form-group"><label>Company</label><input type="text" id="exp-co" placeholder="e.g. Acme Corp"></div>
    <div class="form-row">
      <div class="form-group"><label>Start</label><input type="text" id="exp-s" placeholder="e.g. Jan 2022"></div>
      <div class="form-group"><label>End (blank = Present)</label><input type="text" id="exp-e" placeholder="e.g. Mar 2024"></div>
    </div>
    <div class="form-group"><label>Description</label><textarea id="exp-desc" rows="3" placeholder="What did you do?"></textarea></div>
  </div>
  <div class="modal-foot">
    <button class="btn btn-ghost" onclick="closeM('m-exp')">Cancel</button>
    <button class="btn btn-primary" onclick="saveExp()">Save</button>
  </div>
</div>
</div>

<!-- Education -->
<div class="overlay" id="m-edu">
<div class="modal">
  <div class="modal-head"><div class="modal-title" id="edu-mtitle">Add Education</div><button class="modal-close" onclick="closeM('m-edu')">✕</button></div>
  <div class="modal-body">
    <input type="hidden" id="edu-id">
    <div class="form-group"><label>Institution</label><input type="text" id="edu-inst" placeholder="University / School name"></div>
    <div class="form-group"><label>Degree</label><input type="text" id="edu-deg" placeholder="e.g. Bachelor of Science"></div>
    <div class="form-group"><label>Field of Study</label><input type="text" id="edu-field" placeholder="e.g. Computer Science"></div>
    <div class="form-row">
      <div class="form-group"><label>Start year</label><input type="text" id="edu-s" placeholder="2020"></div>
      <div class="form-group"><label>End year (blank = Present)</label><input type="text" id="edu-e" placeholder="2024"></div>
    </div>
    <div class="form-group"><label>Notes (optional)</label><textarea id="edu-desc" rows="2" placeholder="Honors, awards, activities..."></textarea></div>
  </div>
  <div class="modal-foot">
    <button class="btn btn-ghost" onclick="closeM('m-edu')">Cancel</button>
    <button class="btn btn-primary" onclick="saveEdu()">Save</button>
  </div>
</div>
</div>

<!-- Skill -->
<div class="overlay" id="m-skill">
<div class="modal">
  <div class="modal-head"><div class="modal-title">Add Skill</div><button class="modal-close" onclick="closeM('m-skill')">✕</button></div>
  <div class="modal-body">
    <div class="form-group"><label>Skill name</label><input type="text" id="sk-name" placeholder="e.g. PHP, Figma, React"></div>
    <div class="form-group"><label>Category</label>
      <input type="text" id="sk-cat" placeholder="e.g. Backend, Design, Frontend" list="sk-cats">
      <datalist id="sk-cats"><?php foreach(array_keys($skByCat) as $c): ?><option value="<?=htmlspecialchars($c)?>"><?php endforeach; ?></datalist>
    </div>
    <div class="form-group"><label>Proficiency</label>
      <select id="sk-level">
        <option value="beginner">Beginner</option>
        <option value="intermediate" selected>Intermediate</option>
        <option value="advanced">Advanced</option>
        <option value="expert">Expert</option>
      </select>
    </div>
  </div>
  <div class="modal-foot">
    <button class="btn btn-ghost" onclick="closeM('m-skill')">Cancel</button>
    <button class="btn btn-primary" onclick="saveSkill()">Add Skill</button>
  </div>
</div>
</div>

<!-- Project -->
<div class="overlay" id="m-proj">
<div class="modal">
  <div class="modal-head"><div class="modal-title" id="proj-mtitle">Add Project</div><button class="modal-close" onclick="closeM('m-proj')">✕</button></div>
  <div class="modal-body">
    <input type="hidden" id="proj-id">
    <div class="form-group"><label>Title</label><input type="text" id="proj-title" placeholder="e.g. Portfolio Auth System"></div>
    <div class="form-group"><label>Description</label><textarea id="proj-desc" rows="3" placeholder="What does this project do?"></textarea></div>
    <div class="form-group"><label>Tech stack <small style="color:var(--t2);font-weight:400">(comma-separated)</small></label><input type="text" id="proj-tech" placeholder="PHP, MySQL, CSS"></div>
    <div class="form-row">
      <div class="form-group"><label>GitHub URL</label><input type="url" id="proj-gh" placeholder="https://github.com/..."></div>
      <div class="form-group"><label>Live URL</label><input type="url" id="proj-live" placeholder="https://..."></div>
    </div>
  </div>
  <div class="modal-foot">
    <button class="btn btn-ghost" onclick="closeM('m-proj')">Cancel</button>
    <button class="btn btn-primary" onclick="saveProj()">Save</button>
  </div>
</div>
</div>

<!-- Delete Account -->
<div class="overlay" id="m-delete">
<div class="modal">
  <div class="modal-head"><div class="modal-title" style="color:var(--rd)">Delete Account</div><button class="modal-close" onclick="closeM('m-delete')">✕</button></div>
  <div class="modal-body">
    <div class="alert alert-error"><strong>Warning:</strong> This permanently deletes your account, projects, skills, experience, and education. Cannot be undone.</div>
    <div class="form-group"><label>Enter your password to confirm</label><input type="password" id="del-pw" placeholder="Your current password"></div>
  </div>
  <div class="modal-foot">
    <button class="btn btn-ghost" onclick="closeM('m-delete')">Cancel</button>
    <button class="btn btn-danger" onclick="deleteAcct()">Yes, Delete Everything</button>
  </div>
</div>
</div>

<!-- Toast container -->
<div id="toasts"></div>

<!-- ══ JS ═════════════════════════════════════════ -->
<script>
'use strict';

// ── API helper ────────────────────────────────────────
async function api(data){
  const fd=new FormData();
  for(const[k,v]of Object.entries(data)) fd.append(k,v??'');
  const r=await fetch('profile.php',{method:'POST',body:fd});
  return r.json();
}

// ── Toast ─────────────────────────────────────────────
function toast(msg,type='ok'){
  const el=document.createElement('div');
  el.className='toast '+type; el.textContent=msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>{el.classList.add('out');el.addEventListener('animationend',()=>el.remove(),{once:true})},3000);
}

// ── Modal helpers ─────────────────────────────────────
function openM(id){document.getElementById(id).classList.add('open');document.body.style.overflow='hidden'}
function closeM(id){document.getElementById(id).classList.remove('open');document.body.style.overflow=''}

// close on backdrop
document.querySelectorAll('.overlay').forEach(el=>{
  el.addEventListener('click',e=>{if(e.target===el)closeM(el.id)});
});
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') document.querySelectorAll('.overlay.open').forEach(el=>closeM(el.id));
});

// ── Tabs ──────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn=>{
  btn.addEventListener('click',function(){
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
    this.classList.add('active');
    document.getElementById('tab-'+this.dataset.tab).classList.add('active');
    this.scrollIntoView({behavior:'smooth',block:'nearest',inline:'center'});
  });
});

// ── Hamburger ─────────────────────────────────────────
const ham=document.getElementById('ham'),drw=document.getElementById('drawer');
ham.addEventListener('click',e=>{e.stopPropagation();ham.classList.toggle('open');drw.classList.toggle('open')});
document.addEventListener('click',e=>{if(!ham.contains(e.target)&&!drw.contains(e.target)){ham.classList.remove('open');drw.classList.remove('open')}});

// ── Avatar upload ─────────────────────────────────────
document.getElementById('av-in').addEventListener('change',async function(){
  if(!this.files[0]) return;
  const fd=new FormData(); fd.append('action','upload_avatar'); fd.append('avatar',this.files[0]);
  toast('Uploading…','info');
  const r=await fetch('profile.php',{method:'POST',body:fd}); const d=await r.json();
  if(d.ok){
    toast('Avatar updated!');
    let img=document.getElementById('av-img');
    if(!img){
      img=document.createElement('img'); img.className='av-img'; img.id='av-img';
      const ph=document.getElementById('av-ph'); ph?ph.replaceWith(img):document.querySelector('.av-wrap').prepend(img);
    }
    img.src=d.path;
  } else toast(d.msg||'Upload failed','err');
});

// ── Save profile ──────────────────────────────────────
async function saveProfile(){
  const d=await api({action:'save_profile',
    first_name:$('ep-fn').value, last_name:$('ep-ln').value,
    username:$('ep-un').value,   tagline:$('ep-tg').value,
    bio:$('ep-bio').value,       gender:$('ep-gender').value,
    phone:$('ep-ph').value,      address:$('ep-addr').value,
    location:$('ep-loc').value,  website:$('ep-web').value,
    github:$('ep-gh').value,     linkedin:$('ep-li').value,
    twitter:$('ep-tw').value
  });
  if(d.ok){closeM('m-profile');toast('Profile saved!');setTimeout(()=>location.reload(),700)}
  else toast(d.msg||'Error','err');
}

// ── Experience ────────────────────────────────────────
function openExpModal(e){
  // Bug fix #3: never use new Date('YYYY-MM-DD') — parse manually if needed
  $('exp-mtitle').textContent=e?'Edit Experience':'Add Experience';
  $('exp-id').value   =e?e.id:'';
  $('exp-pos').value  =e?e.position:'';
  $('exp-co').value   =e?e.company:'';
  $('exp-s').value    =e?e.date_start:'';
  $('exp-e').value    =e?e.date_end:'';
  $('exp-desc').value =e?e.description:'';
  openM('m-exp');
}
async function saveExp(){
  const id=$('exp-id').value;
  const d=await api({action:id?'edit_experience':'add_experience',id,
    position:$('exp-pos').value, company:$('exp-co').value,
    date_start:$('exp-s').value, date_end:$('exp-e').value,
    description:$('exp-desc').value
  });
  if(d.ok){closeM('m-exp');toast(id?'Updated!':'Added!');setTimeout(()=>location.reload(),600)}
  else toast(d.msg||'Error','err');
}

// ── Education ─────────────────────────────────────────
function openEduModal(e){
  $('edu-mtitle').textContent=e?'Edit Education':'Add Education';
  $('edu-id').value   =e?e.id:'';
  $('edu-inst').value =e?e.institution:'';
  $('edu-deg').value  =e?e.degree:'';
  $('edu-field').value=e?e.field:'';
  $('edu-s').value    =e?e.year_start:'';
  $('edu-e').value    =e?e.year_end:'';
  $('edu-desc').value =e?e.description:'';
  openM('m-edu');
}
async function saveEdu(){
  const id=$('edu-id').value;
  const d=await api({action:id?'edit_education':'add_education',id,
    institution:$('edu-inst').value, degree:$('edu-deg').value,
    field:$('edu-field').value,      year_start:$('edu-s').value,
    year_end:$('edu-e').value,       description:$('edu-desc').value
  });
  if(d.ok){closeM('m-edu');toast(id?'Updated!':'Added!');setTimeout(()=>location.reload(),600)}
  else toast(d.msg||'Error','err');
}

// ── Skills ────────────────────────────────────────────
async function saveSkill(){
  const name=$('sk-name').value.trim();
  if(!name){toast('Skill name required','err');return}
  const d=await api({action:'add_skill',name,category:$('sk-cat').value||'General',proficiency:$('sk-level').value});
  if(d.ok){closeM('m-skill');toast('Skill added!');setTimeout(()=>location.reload(),600)}
  else toast(d.msg||'Error','err');
}
async function delSkill(id){
  const d=await api({action:'delete_skill',id});
  if(d.ok){document.getElementById('sk'+id)?.remove();toast('Removed')}
  else toast(d.msg||'Error','err');
}

// ── Projects ──────────────────────────────────────────
function openProjModal(p){
  $('proj-mtitle').textContent=p?'Edit Project':'Add Project';
  $('proj-id').value   =p?p.id:'';
  $('proj-title').value=p?p.title:'';
  $('proj-desc').value =p?p.description:'';
  $('proj-tech').value =p?p.tech_stack:'';
  $('proj-gh').value   =p?p.github_url:'';
  $('proj-live').value =p?p.live_url:'';
  openM('m-proj');
}
async function saveProj(){
  const id=$('proj-id').value;
  const d=await api({action:id?'edit_project':'add_project',id,
    title:$('proj-title').value, description:$('proj-desc').value,
    tech_stack:$('proj-tech').value, github_url:$('proj-gh').value, live_url:$('proj-live').value
  });
  if(d.ok){closeM('m-proj');toast(id?'Updated!':'Added!');setTimeout(()=>location.reload(),600)}
  else toast(d.msg||'Error','err');
}

// ── Generic delete ────────────────────────────────────
const ACT={experience:'delete_experience',education:'delete_education',project:'delete_project'};
async function del(type,id,elemId){
  if(!confirm('Delete this? Cannot be undone.')) return;
  const d=await api({action:ACT[type],id});
  if(d.ok){document.getElementById(elemId)?.remove();toast('Deleted')}
  else toast(d.msg||'Error','err');
}

// ── 2FA toggle ────────────────────────────────────────
document.getElementById('twofa-tog').addEventListener('change',async function(){
  const st=this.checked?1:0;
  const d=await api({action:'toggle_2fa',state:st});
  const lbl=document.getElementById('twofa-lbl');
  if(d.ok){
    lbl.textContent=st?'● Enabled':'○ Disabled';
    lbl.className='twofa-status '+(st?'on':'off');
    toast('2FA '+(st?'enabled':'disabled'));
  } else {this.checked=!this.checked;toast('Could not update','err')}
});

// ── Revoke sessions ───────────────────────────────────
async function revokeAll(){
  if(!confirm('Revoke all trusted devices?')) return;
  const d=await api({action:'revoke_sessions'});
  d.ok?toast('All sessions revoked'):toast(d.msg||'Error','err');
}

// ── Change password ───────────────────────────────────
async function changePw(){
  const c=$('cp-cur').value,n=$('cp-new').value,co=$('cp-con').value;
  if(!c||!n||!co){toast('Fill all fields','err');return}
  const d=await api({action:'change_password',current_password:c,new_password:n,confirm_password:co});
  if(d.ok){toast('Password changed!');['cp-cur','cp-new','cp-con'].forEach(i=>$(i).value='');strBar('')}
  else toast(d.msg||'Error','err');
}

// strength bar
function strBar(v){
  const s=[/[A-Z]/.test(v),/[a-z]/.test(v),/[0-9]/.test(v),/[^A-Za-z0-9]/.test(v),v.length>=8];
  const sc=s.filter(Boolean).length;
  const c=['#1a1a1a','#1a1a1a','#1a1a1a','#1a1a1a'];
  if(sc>=1)c[0]='#ef4444'; if(sc>=2)c[1]='#f59e0b'; if(sc>=4)c[2]='#22c55e'; if(sc>=5)c[3]='#00e5cc';
  for(let i=1;i<=4;i++) document.getElementById('sb'+i).style.background=c[i-1];
  $('sb-lbl').textContent=v?(['','Weak','Fair','Good','Strong','Very strong ✓'][sc]||'Very strong ✓'):'Enter a password';
}

// ── Delete account ────────────────────────────────────
async function deleteAcct(){
  const pw=$('del-pw').value;
  if(!pw){toast('Enter your password','err');return}
  const d=await api({action:'delete_account',password:pw});
  if(d.ok){toast('Account deleted. Goodbye.');setTimeout(()=>location.href=d.redirect||'register.php',1200)}
  else toast(d.msg||'Incorrect password','err');
}

// ── Password show/hide ────────────────────────────────
function togPass(id,btn){const i=$(id);i.type=i.type==='password'?'text':'password';btn.textContent=i.type==='password'?'👁':'🙈'}

// ── Shorthand ─────────────────────────────────────────
function $(id){return document.getElementById(id)}

// ── Mobile: project overlay always shown ──────────────
// Bug fix #5: set opacity:1 on touch devices — no hover on mobile
(function(){
  const touch=window.matchMedia('(max-width:768px)').matches||'ontouchstart' in window;
  if(touch){
    document.querySelectorAll('.proj-overlay').forEach(el=>{
      el.style.cssText='opacity:1!important;position:static;background:transparent;border-radius:0;padding:0;margin-top:12px;justify-content:flex-start;gap:8px;';
    });
  }
})();
</script>
</body>
</html>
