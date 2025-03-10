<?php

namespace Hlmqz\JWT\Traits;
use Hlmqz\JWT\Exceptions\SignatureInvalidException;

trait validateRSA
{

// ==================================================================================

	protected function validateSignatureRSA(
		string $payload,
		string $key,
		?string $algo = 'RS256',
	):?string
	{
		if(!isset($this->algos[$algo])) 
			throw new SignatureInvalidException("The reference to the algorithm to use is not valid");

		openssl_sign($payload, $signature, $key, $this->algos[$algo]);

		return base64_encode($signature);
	}

// ==================================================================================
}
