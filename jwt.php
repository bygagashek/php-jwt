<?php

require 'vendor/autoload.php';
use Firebase\JWT\JWT;

class JWTManager {
    private static $key = 'your_secret_key';

    public static function generateToken($username) {
        $payload = array(
            'username' => $username
        );

        return JWT::encode($payload, self::$key);
    }

    public static function validateToken($token) {
        try {
            return JWT::decode($token, self::$key, array('HS256'));
        } catch (Exception $e) {
            return false;
        }
    }
}
