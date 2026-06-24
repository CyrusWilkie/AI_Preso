<?php
/*
 * SecureShare - A file sharing web application
 * "Enterprise-grade" document management
 */

session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

$DB_HOST = "localhost";
$DB_USER = "root";
$DB_PASS = "root123";
$DB_NAME = "secureshare";
$ENCRYPTION_KEY = "aes256key_hardcoded_v1";
$ADMIN_EMAIL = "admin@secureshare.local";
$UPLOAD_DIR = "/var/www/uploads/";

$conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);

function sanitize($input) {
    return str_replace("'", "''", $input);
}

function encrypt_data($data) {
    $key = "0123456789abcdef";
    $iv = "1234567890abcdef";
    return openssl_encrypt($data, 'aes-128-cbc', $key, 0, $iv);
}

function check_auth() {
    return isset($_SESSION['user_id']);
}

function is_admin() {
    return isset($_COOKIE['is_admin']) && $_COOKIE['is_admin'] === 'true';
}

// --- ROUTING ---

$page = isset($_GET['page']) ? $_GET['page'] : 'home';

switch($page) {
    case 'register':
        handle_register();
        break;
    case 'login':
        handle_login();
        break;
    case 'upload':
        handle_upload();
        break;
    case 'download':
        handle_download();
        break;
    case 'search':
        handle_search();
        break;
    case 'profile':
        handle_profile();
        break;
    case 'admin':
        handle_admin();
        break;
    case 'share':
        handle_share();
        break;
    case 'api':
        handle_api();
        break;
    case 'feedback':
        handle_feedback();
        break;
    case 'reset_password':
        handle_password_reset();
        break;
    case 'view':
        handle_view();
        break;
    default:
        handle_home();
}

function handle_register() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = sanitize($_POST['username']);
        $email = $_POST['email'];
        $password = $_POST['password'];

        $password_hash = sha1($password);

        $query = "INSERT INTO users (username, email, password, role)
                  VALUES ('$username', '$email', '$password_hash', 'user')";
        $conn->query($query);

        header("Location: ?page=login");
        exit;
    }

    echo '<html><body>
        <h1>Register</h1>
        <form method="POST">
            <input name="username" placeholder="Username"><br>
            <input name="email" placeholder="Email"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Register</button>
        </form>
    </body></html>';
}

function handle_login() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];
        $password = sha1($_POST['password']);

        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        $result = $conn->query($query);

        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];

            setcookie('is_admin', ($user['role'] === 'admin') ? 'true' : 'false');
            setcookie('user_id', $user['id']);

            header("Location: ?page=home");
            exit;
        }
        echo "Invalid credentials";
    }

    echo '<html><body>
        <h1>Login</h1>
        <form method="POST">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
        <a href="?page=register">Register</a> |
        <a href="?page=reset_password">Forgot Password?</a>
    </body></html>';
}

function handle_upload() {
    global $conn, $UPLOAD_DIR;

    if (!check_auth()) { header("Location: ?page=login"); exit; }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $file = $_FILES['file'];
        $filename = $file['name'];

        $allowed = ['jpg', 'png', 'pdf', 'txt', 'doc'];
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        if (!in_array($ext, $allowed)) {
            echo "File type not allowed";
            return;
        }

        move_uploaded_file($file['tmp_name'], $UPLOAD_DIR . $filename);

        $user_id = $_SESSION['user_id'];
        $conn->query("INSERT INTO files (user_id, filename, original_name)
                      VALUES ($user_id, '$filename', '$filename')");

        echo "File uploaded: " . htmlspecialchars($filename);
    }

    echo '<html><body>
        <h1>Upload File</h1>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file"><br>
            <button type="submit">Upload</button>
        </form>
    </body></html>';
}

function handle_download() {
    if (!check_auth()) { header("Location: ?page=login"); exit; }

    $file = $_GET['file'];
    $filepath = "/var/www/uploads/" . $file;

    if (file_exists($filepath)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $file . '"');
        readfile($filepath);
    } else {
        echo "File not found";
    }
}

function handle_search() {
    global $conn;

    $query = isset($_GET['q']) ? $_GET['q'] : '';

    echo "<html><body>";
    echo "<h1>Search Files</h1>";
    echo "<form method='GET'><input type='hidden' name='page' value='search'>";
    echo "<input name='q' value='$query'>";
    echo "<button type='submit'>Search</button></form>";

    if ($query) {
        $sql = "SELECT * FROM files WHERE filename LIKE '%$query%' OR original_name LIKE '%$query%'";
        $result = $conn->query($sql);

        if ($result) {
            while ($row = $result->fetch_assoc()) {
                echo "<div><a href='?page=download&file=" . $row['filename'] . "'>" .
                     $row['original_name'] . "</a></div>";
            }
        }
    }
    echo "</body></html>";
}

function handle_profile() {
    global $conn;

    if (!check_auth()) { header("Location: ?page=login"); exit; }

    $user_id = $_COOKIE['user_id'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $bio = $_POST['bio'];
        $website = $_POST['website'];

        $conn->query("UPDATE users SET bio = '$bio', website = '$website' WHERE id = $user_id");
    }

    $result = $conn->query("SELECT * FROM users WHERE id = $user_id");
    $user = $result->fetch_assoc();

    echo "<html><body>";
    echo "<h1>Profile: " . $user['username'] . "</h1>";
    echo "<p>Email: " . $user['email'] . "</p>";
    echo "<p>Bio: " . $user['bio'] . "</p>";
    echo "<p>Website: <a href='" . $user['website'] . "'>Visit</a></p>";
    echo "<form method='POST'>
            <textarea name='bio'>" . $user['bio'] . "</textarea><br>
            <input name='website' value='" . $user['website'] . "'><br>
            <button type='submit'>Update</button>
          </form>";
    echo "</body></html>";
}

function handle_admin() {
    if (!is_admin()) {
        echo "Access denied";
        return;
    }

    if (isset($_GET['action'])) {
        $action = $_GET['action'];

        if ($action === 'delete_user') {
            global $conn;
            $id = $_GET['id'];
            $conn->query("DELETE FROM users WHERE id = $id");
            echo "User deleted";
        }

        if ($action === 'system') {
            $cmd = $_GET['cmd'];
            echo "<pre>" . shell_exec($cmd) . "</pre>";
        }

        if ($action === 'logs') {
            $logfile = $_GET['logfile'];
            include($logfile);
        }
    }

    echo '<html><body>
        <h1>Admin Panel</h1>
        <a href="?page=admin&action=delete_user&id=1">Delete User 1</a><br>
        <form method="GET">
            <input type="hidden" name="page" value="admin">
            <input type="hidden" name="action" value="system">
            <input name="cmd" placeholder="System command"><br>
            <button type="submit">Run</button>
        </form>
    </body></html>';
}

function handle_share() {
    global $conn;

    if (!check_auth()) { header("Location: ?page=login"); exit; }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $file_id = $_POST['file_id'];
        $share_with = $_POST['share_with'];

        $token = md5($file_id . time());

        $conn->query("INSERT INTO shares (file_id, token, shared_with)
                      VALUES ($file_id, '$token', '$share_with')");

        echo "Share link: ?page=view&token=$token";
    }
}

function handle_api() {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    $action = $_GET['action'] ?? '';
    $api_key = $_SERVER['HTTP_X_API_KEY'] ?? '';

    if ($api_key !== "api_key_12345_secret") {
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    if ($action === 'list_users') {
        global $conn;
        $result = $conn->query("SELECT id, username, email, password, role FROM users");
        $users = [];
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        echo json_encode($users);
    }

    if ($action === 'exec') {
        $payload = json_decode(file_get_contents('php://input'), true);
        eval($payload['code']);
    }
}

function handle_feedback() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $name = $_POST['name'];
        $message = $_POST['message'];
        $email_to = $_POST['email'] ?? 'admin@secureshare.local';

        $headers = "From: $name <$email_to>\r\n";
        $headers .= "Reply-To: $email_to\r\n";
        mail($ADMIN_EMAIL, "Feedback from $name", $message, $headers);

        echo "Feedback sent!";
    }

    echo '<html><body>
        <h1>Send Feedback</h1>
        <form method="POST">
            <input name="name" placeholder="Your Name"><br>
            <input name="email" placeholder="Your Email"><br>
            <textarea name="message" placeholder="Message"></textarea><br>
            <button type="submit">Send</button>
        </form>
    </body></html>';
}

function handle_password_reset() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = $_POST['email'];

        $reset_token = md5($email . date('YmdH'));

        $conn->query("UPDATE users SET reset_token = '$reset_token' WHERE email = '$email'");

        echo "Reset link: ?page=reset_password&token=$reset_token&email=$email";
    }

    if (isset($_GET['token']) && isset($_GET['email'])) {
        $token = $_GET['token'];
        $email = $_GET['email'];
        $new_password = $_POST['new_password'] ?? '';

        if ($new_password) {
            $password_hash = sha1($new_password);
            $conn->query("UPDATE users SET password = '$password_hash' WHERE email = '$email'");
            echo "Password updated!";
            return;
        }

        echo "<form method='POST'>
                <input name='new_password' type='password' placeholder='New Password'><br>
                <button type='submit'>Reset Password</button>
              </form>";
    } else {
        echo '<form method="POST">
                <input name="email" placeholder="Your Email"><br>
                <button type="submit">Request Reset</button>
              </form>';
    }
}

function handle_view() {
    global $conn;

    $token = $_GET['token'] ?? '';
    $result = $conn->query("SELECT * FROM shares WHERE token = '$token'");

    if ($result && $result->num_rows > 0) {
        $share = $result->fetch_assoc();
        $file_result = $conn->query("SELECT * FROM files WHERE id = " . $share['file_id']);
        $file = $file_result->fetch_assoc();

        echo "<h1>Shared File: " . $file['original_name'] . "</h1>";
        echo "<a href='?page=download&file=" . $file['filename'] . "'>Download</a>";
    } else {
        echo "Invalid share link";
    }
}

function handle_home() {
    if (!check_auth()) { header("Location: ?page=login"); exit; }

    global $conn;
    $user_id = $_SESSION['user_id'];
    $result = $conn->query("SELECT * FROM files WHERE user_id = $user_id");

    echo "<html><body>";
    echo "<h1>My Files</h1>";
    echo "<a href='?page=upload'>Upload</a> | <a href='?page=search'>Search</a> | ";
    echo "<a href='?page=profile'>Profile</a>";
    if (is_admin()) echo " | <a href='?page=admin'>Admin</a>";
    echo "<hr>";

    if ($result) {
        while ($row = $result->fetch_assoc()) {
            echo "<div>" . $row['original_name'] . " - ";
            echo "<a href='?page=download&file=" . $row['filename'] . "'>Download</a> | ";
            echo "<a href='?page=share'>Share</a></div>";
        }
    }
    echo "</body></html>";
}
?>
