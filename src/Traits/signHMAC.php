<?php

namespace Hlmqz\JWT\Traits;
use Hlmqz\JWT\Exceptions\SignatureInvalidException;

trait signHMAC
{

	protected $algos = [
		'HS256' => 'sha256',
		'HS386' => 'sha384',
		'HS512' => 'sha512',
	];

	protected function makeSignature(
		string $payload,
		string $key,
		?string $algo = 'HS256',
	):?string
	{
		if(!isset($this->algos[$algo])) 
			throw new SignatureInvalidException("The reference to the algorithm to use is not valid");

		return base64_encode(hash_hmac($this->algos[$algo], $payload, $key, true));
	}
}