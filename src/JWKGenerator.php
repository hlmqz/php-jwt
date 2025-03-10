<?php

namespace Hlmqz\JWT;

use Hlmqz\JWT\Traits\signRSA;
use Hlmqz\JWT\Exceptions\SignatureInvalidException;

class JWKGenerator extends JWTGenerator
{
	use signRSA;

//===================================================================================

	public static function newKeyPair(int $bits = 2048):array
	{
		if($bits < 2048 || $bits % 128 != 0)
				throw new \UnexpectedValueException(
					"The value must be greater than or equal to 2048 and multiple of 128"
				);

		$privateKeyStream = openssl_pkey_new([
			"private_key_bits" => $bits,
			"private_key_type" => OPENSSL_KEYTYPE_RSA,
		]);

		if(!$privateKeyStream)
				throw new \SignatureInvalidException("Unable to use openssl functions");

		openssl_pkey_export($privateKeyStream, $privateKey);

		$publicKey = openssl_pkey_get_details($privateKeyStream)['key'];

		return compact('privateKey', 'publicKey');
	}

//===================================================================================

	public static function getPublicKey(string|object $privateKey):string|array
	{
		if(gettype($privateKey) == 'string')
			$privateKeyStream = openssl_pkey_get_private($privateKey);
		else
			$privateKeyStream = $privateKey;

		if(
				gettype($privateKeyStream) == 'object'
				&& $privateKeyStream::class == 'OpenSSLAsymmetricKey'
		)
			return openssl_pkey_get_details($privateKeyStream)['key'];

		throw new \UnexpectedValueException(
			"The parameter is not text or stream of a private key"
		);
	}

//===================================================================================
}
