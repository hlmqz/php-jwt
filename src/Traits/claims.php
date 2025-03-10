<?php

namespace Hlmqz\JWT\Traits;
use Hlmqz\JWT\Exceptions\ClaimInvalidException;

trait claims
{

	public string $issuer
	{
		set(string $value){ $this->setClaim('iss',$value); }
		get{ return $this->claimsData['iss'] ?? ''; }
	}

	public string $subject
	{
		set(string $value){ $this->setClaim('sub',$value); }
		get{ return $this->claimsData['sub'] ?? ''; }
	}

	public string|array $audience
	{
		set(string|array $value){ $this->setClaim('aud',$value); }
		get{ return $this->claimsData['aud'] ?? ''; }
	}

	protected $claims = [
		'iss', // Issuer
		'sub', // Subject
		'aud', // Audience
		/*
		Claims auto management:
		iat, jti, nbf, exp
		*/
	];

	protected $claimsData = [];

//===================================================================================

	public function setClaim(string $name, $value):void
	{
		$named = mb_strtolower($name);
		if(!in_array($named, $this->claims))
			throw new ClaimInvalidException(
				"The name of the claim is non-standard: ".implode(', ', $this->claims)
			);

		if( !$value && isset($this->claimsData[$named]))
			unset($this->claimsData[$named]);
		else
			$this->claimsData[$named] = $value;
	}

//===================================================================================
}
