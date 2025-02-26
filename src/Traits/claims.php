<?php

namespace Hlmqz\JWT\Traits;
use Hlmqz\JWT\Exceptions\ClaimInvalidException;

trait claims
{
	protected $claims = [
		'iss', 'sub', 'aud', 'exp',
		/*
		Claims auto management:
		iat, jti, nbf
		*/
	];

	protected $claimsData = [];

//===================================================================================

	public function setClaim(string $name, $value):void
	{
		$named = mb_strtolower($name);
		if(!in_array($named, $this->claims))
			throw new ClaimInvalidException("The name of the claim is non-standard");

		if(is_null($value) && isset($this->claimsData[$named]))
			unset($this->claimsData[$named]);
		else
			$this->claimsData[$named] = $value;
	}

//===================================================================================
}
