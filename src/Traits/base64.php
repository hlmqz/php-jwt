<?php

namespace Hlmqz\JWT\Traits;

trait base64
{
// ==================================================================================

	private function clearBase64(string $base64):string
	{
		return str_replace(['+','/','='], ['-','_',''], $base64);
	}

// ==================================================================================

	private function completeBase64(string $uri64):string
	{
		$base64 = str_replace(['-','_'],['+','/'], $uri64);
		return str_pad($base64, ceil( strlen($base64)/4 ) * 4, '=');
	}

// ==================================================================================

	private function fromUri64(string $uri64, $inArray = true):\StdClass|array|null
	{
		return json_decode(base64_decode($this->completeBase64($uri64)), $inArray);
	}

//===================================================================================
}
