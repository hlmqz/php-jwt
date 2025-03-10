<?php

namespace Hlmqz\JWT;
use Hlmqz\JWT\Traits\base64;
use Hlmqz\JWT\Traits\signHMAC;
use Hlmqz\JWT\Exceptions\TokenInvalidException;

class JWTChecker
{
	use base64, signHMAC;

	protected(set) \StdClass|array|null $headers = null;
	protected(set) \StdClass|array|null $content = null;
	protected(set) \StdClass|array $body = [];
	protected(set) bool $isValid = false;
	protected(set) array $errors = [];
	protected string|null $verify = null;

	protected array $algos;
	protected string $defaultAlgo;

	public string $keyIdentifier
	{
		get { return $this->headers['kid'] ?? '';}
	}

	public string $token
	{
		set(string $value)
		{
			$this->token = (function() use ($value)
			{
				if(!$value) return '';

				$parts = explode('.', $value);

				if(count($parts) !== 3)
						throw new TokenInvalidException("The token is not in a valid format");

				$this->errors = [];
				return $value;
			})();

			if($this->token)
				$this->processToken();
		}
	}

	public string $key = ''
	{
		set(string $value)
		{
			$this->key = $value ? $value : '';
			if($this->key)
				$this->processToken();
		}
	}

//===================================================================================

	function __construct(string $token, ?string $key = '')
	{
		$this->setDefaults();
		$this->token = $token;
		$this->key = $key;
		$this->processToken();
	}

//===================================================================================

	private function processToken():void
	{
		$this->isValid = false;
		if(!$this->token)
		{
			$this->headers = null;
			$this->body = null;
			$this->verify = null;
			return;
		}

		[$encodeHeaders, $encodeBody, $verify] = explode('.', $this->token);

		$headers = $this->fromUri64($encodeHeaders);
		$body = $this->fromUri64($encodeBody);

		$this->headers = $headers;

		if(!$this->key)
			return;

		if(
			!$this->checkSignature(
				"{$encodeHeaders}.{$encodeBody}", $this->key,
				$this->completeBase64($verify), $headers['alg'],
			)
		)
		{
			$this->errors[] = "Integrity check failed";
			return;
		}

		if($body['exp'] > $body['iat'] && time() > $body['exp'])
			$this->errors[] = "JWT validity time has expired";

		if(time() < $body['nbf'])
			$this->errors[] = "JWT validity time has not started";

		if($this->errors) return;

		$this->isValid = true;
		$this->content = $body['content'] ?? null;
		$this->body = $body;
		$this->verify = $verify;
	}

// ==================================================================================
}
