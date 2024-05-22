<?php

require 'config.php';
require 'jwt.php';

$conn = new PDO("mysql:host=$host;dbname=$db", $user, $password);

function registerUser($username, $password) {
    global $conn;

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':password', $hashedPassword);
    $stmt->execute();

    return $stmt->rowCount() > 0;
}

function loginUser($username, $password) {
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->bindParam(':username', $username);
    $stmt->execute();

    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        $token = JWTManager::generateToken($username);
        return $token;
    }

    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (isset($data['action'])) {
        if ($data['action'] === 'register') {
            $username = $data['username'];
            $password = $data['password'];

            $success = registerUser($username, $password);

            if ($success) {
                echo json_encode(['message' => 'Registration successful']);
            } else {
                echo json_encode(['error' => 'Registration failed']);
            }
        } elseif ($data['action'] === 'login') {
            $username = $data['username'];
            $password = $data['password'];

            $token = loginUser($username, $password);

            if ($token) {
                echo json_encode(['token' => $token]);
            } else {
                echo json_encode(['error' => 'Invalid credentials']);
            }
        }
    }
}
