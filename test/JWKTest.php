<?php

use PHPUnit\Framework\TestCase;
use Hlmqz\JWT\JWKGenerator;
use Hlmqz\JWT\JWKChecker;


class JWKTest extends TestCase
{

// ==================================================================================

	private(set) string $privateKey;
	private(set) string $publicKey;

	protected function setUp(): void
	{
		$keyPair = JWKGenerator::newKeyPair();

		$this->privateKey = $keyPair['privateKey'];
		$this->publicKey = $keyPair['publicKey'];
	}

// ==================================================================================

	public function testGenerateJWK()
	{
		$jwt = new JWKGenerator($this->privateKey);

		$jwt->content = [
			'user' => 1,
			'role' => 'basic',
		];

		$token = $jwt->getToken();

		$this->assertIsString($token);
		$this->assertMatchesRegularExpression(
			'/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/',
			$token,
		);
	}

// ==================================================================================

	public function testValidationJWK()
	{
		$jwt = new JWKGenerator($this->privateKey);

		$jwt->content = [
			'user' => 1,
			'role' => 'basic',
		];

		$token = $jwt->getToken();

		$checker = new JWKChecker($token, $this->publicKey);

		$this->assertTrue($checker->isValid);
	}

// ==================================================================================
}
