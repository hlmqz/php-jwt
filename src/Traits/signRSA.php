<?php

namespace Hlmqz\JWT\Traits;
use Hlmqz\JWT\Exceptions\SignatureInvalidException;

trait signRSA
{
// ==================================================================================

	protected function setDefaults()
	{

		$this->algos = [
			'RS256' => OPENSSL_ALGO_SHA256,
			'RS386' => OPENSSL_ALGO_SHA384,
			'RS512' => OPENSSL_ALGO_SHA512,
		];

		$this->defaultAlgo = 'RS256';
	}

// ==================================================================================

	protected function makeSignature(
		string $payload,
		string $privateKey,
		?string $algo = 'RS256',
	):?string
	{
		if(!isset($this->algos[$algo])) 
			throw new SignatureInvalidException("The reference to the algorithm to use is not valid");

		openssl_sign($payload, $signature, $privateKey, $this->algos[$algo]);

		return base64_encode($signature);
	}

// ==================================================================================

	protected function checkSignature(
		string $payload,
		string $publicKey,
		string $sign,
		?string $algo,
	):bool
	{
		return openssl_verify($payload, base64_decode($sign), $publicKey, $this->algos[$algo]);
	}

// ==================================================================================
}
