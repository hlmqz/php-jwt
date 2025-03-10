<?php

namespace Hlmqz\JWT\Traits;
use Hlmqz\JWT\Exceptions\SignatureInvalidException;

trait signHMAC
{
// ==================================================================================

	protected function setDefaults()
	{
			$this->algos = [
				'HS256' => 'sha256',
				'HS386' => 'sha384',
				'HS512' => 'sha512',
			];

			$this->defaultAlgo = 'HS256';
	}

// ==================================================================================

	protected function makeSignature(
		string $payload,
		string $key,
		?string $algo = 'HS256',
	):?string
	{

		if(!isset($this->algos[$algo])) 
			throw new SignatureInvalidException(
				"({$algo}) The reference to the algorithm to use is not valid"
			);

		return base64_encode(hash_hmac($this->algos[$algo], $payload, $key, true));
	}

// ==================================================================================

	protected function checkSignature(
		string $payload,
		string $key,
		string $sign,
		?string $algo,
	):bool
	{
		return $sign == $this->makeSignature($payload, $key, $algo);
	}

// ==================================================================================
}
