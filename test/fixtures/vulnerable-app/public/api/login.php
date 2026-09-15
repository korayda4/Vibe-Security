<?php
$email = $_POST['email'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE email = '" . $email . "' AND password = '" . md5($password) . "'";
$result = $mysqli->query($query);

$hashed = sha1($password);

echo "<h1>Welcome " . $_GET['name'] . "</h1>";
echo $_GET['bio'];

$stmt = $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
?>
