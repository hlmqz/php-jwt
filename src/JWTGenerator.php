<?php

namespace Hlmqz\JWT;

use Hlmqz\JWT\Traits\claims;
use Hlmqz\JWT\Traits\base64;
use Hlmqz\JWT\Traits\signHMAC;

class JWTGenerator
{
	use claims, base64, signHMAC;

	public \StdClass|array $content;
	protected array $algos;
	protected string $defaultAlgo;
	public string $keyIdentifier = '';
	public array $headers
	{
		get {return $this->getHeaders();}
	}

	// if the token uses "not before", seconds will be added to the start time
	public int $notBeforeAdd = 0
	{
		set(int $value)
		{
			if($value < 0) $value = 0;
			$this->notBeforeAdd = $value;
		}
	}

	// seven days in seconds, but with zero (0) it will be without time validation
	public int $timeLife = (60*60*24*7)
	{
		set(int $value)
		{
			if($value < 0) $value = 0;
			$this->timeLife = $value;
		}
	}

	public string $algo
	{
		set(string $value)
		{
			$this->algo = ($this->algos[$value] ?? false ? $value : $this->defaultAlgo);
		}
	}

//===================================================================================

	function __construct(public ?string $key = null)
	{
		$this->setDefaults();
		$this->algo = $this->defaultAlgo;
	}

//===================================================================================

	protected function getHeaders():array
	{
		return [
			'alg' => $this->algo,
			'typ' => 'JWT',
			'kid' => $this->keyIdentifier,
		];
	}

//===================================================================================

	protected function getBody():array
	{
		$t = time();

		$body = array_merge(
			$this->claimsData,
			[
				'iat' => $t,
				'nbf' => $t + $this->notBeforeAdd,
				'exp' => $t + $this->timeLife,
				'jti' => base64_encode(random_bytes(36)),
			],
		);

		if($this->content ?? false)
			$body['content'] = (array)$this->content;

		return $body;
	}

//===================================================================================

protected function encode(\StdClass|array $data):string
{
	return $this->clearBase64(
		base64_encode(json_encode($data, JSON_UNESCAPED_SLASHES))
	);
}

//===================================================================================

protected function getPayload():string
{
	$encodeHeaders = $this->encode($this->getHeaders());
	$encodeBody = $this->encode($this->getBody());

	return "{$encodeHeaders}.{$encodeBody}";
}

//===================================================================================

public function getToken():string
{
	if(!$this->key)
		throw new \UnexpectedValueException("There is no key to generate JWT");

	$payload = $this->getPayload();
	$hash = $this->makeSignature($payload, $this->key, $this->algo);

	return $this->clearBase64("{$payload}.{$hash}");
}

//===================================================================================
}
