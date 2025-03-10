<?php

use PHPUnit\Framework\TestCase;
use Hlmqz\JWT\JWTGenerator;
use Hlmqz\JWT\JWTChecker;


class JWTTest extends TestCase
{

// ==================================================================================

	private(set) string $secretKey;

	protected function setUp(): void
	{
		$this->secretKey = base64_encode(random_bytes(96));
	}

// ==================================================================================

	public function testGenerateJWT()
	{
		$jwt = new JWTGenerator($this->secretKey);

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

	public function testValidationJWT()
	{
		$jwt = new JWTGenerator($this->secretKey);

		$jwt->content = [
			'user' => 1,
			'role' => 'basic',
		];

		$token = $jwt->getToken();

		$checker = new JWTChecker($token, $this->secretKey);

		$this->assertTrue($checker->isValid);
	}

// ==================================================================================
}
