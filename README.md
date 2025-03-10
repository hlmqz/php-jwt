# PHP 8.4  - JWT (JSON Web Token)

Este Paquete se creo para implementar la utilidad de generar JWT (y JWK) de manera sencilla,
con funcionalidades no atadas a frameworks pero que se pueden facilmente incluir en uno.

Este paquete permite generar JWT de manera dinámica y con token diferentes así sean con los mismos
datos o desde la misma instancia.

### Requerimientos

- PHP 8.4 o Mayor
- OpenSSL para PHP habilitado

Se usa explicitamente esta versión, porque implementa nuevas funcionalidades como visibilidad
asimetrica de atributos de clase y los hooks de atributos de clase.

## Creación de Token JWT

Generación de un token

```php

use Hlmqz\JWT\JWTGenerator;

$jwt = new JWTGenerator($secretKey);

 // también se puede definir la secret key posteriormente:

$jwt->key = $secreetKey;

// puede agregar datos de contenido:
// array | Object

$jwt->content = [
	'firstname' => 'John',
	'lastname' => 'Doe',
	'rol' => 'user',
];

// Obtener token:
/*
 OPCIONAL: puede establecer un KeyIdentifier para posteriormente saber qué palabra secreta uso,
 claramente no debe poner la palabra secreta directamente en KeyIdentifier.
*/

$jwt->keyIdentifier = '2025-03-01-537475';

// Ahora para obtener el token basta con la siguiente instrucción

$jwt->getToken();

```

con estas pocas lineas ya tiene un JWT seguro respecto a la secretKey otorgada, dinamismo completo.

Aunque las posiblidades de incluir mas información, limite de validez, e inclusive validez desde,
se pueden establecer en los claims de la siguiente manera antes de invocar `getToken`:

```php

// Estos valores, están disponibles pero no son obligaotrios

// establecer el editor del token:
$jwt->issuer = "https://domain.com/"; // iss

// establecer el Sujeto del token:
$jwt->subject = "4c2aefa3-5657-47b9-8158-f0b785d0cb59"; // sub

// establecer destinataros del token:
$jwt->audience = "https://domain.com/"; // sub

/*

los valores de issuer y Subject son string, pero Audience puede ser String o Array de Strings.


también es usable directamente si conoce el claim con:

*/

$jwt->setClaim("iss", "https://domain.com/");

/*

los claims con su atributos usables son:

iss => issuer
sub => subject
aud => audience

*/

```

## Validación de Token JWT

La intensionalidad de un token es poder validar que todavía esté activo, para realizar
esto también es muy sencillo como en el siguiente ejemplo:

```php

use Hlmqz\JWT\JWTChecker;

/*
donde $token es el token generado anteriormente y ahora usado por un cliente y
$secretKey es la palabra secreta con la cual se generó el token.
*/
$jwtCkeck = new JWTChecker($token, $secretKey);
/*
en dado caso de querer saber la referencia de la palabra secreta paa posteriormente procesar,
instnciando solo con el token.
*/

$nameSecret = $jwtCkeck->keyIdentifier;

//con $nameSecret puede cargar o llamar el valor para $secretKey
$jwtCkeck->key = $secretKey;

// basta con preguntar si es válido, otorgará los datos del contenido.

if($$jwtCkeck->isValid){
	// con el atributo content obotiene el mismo contenido establecido al construir el token.
	$content = $jwtCkeck->content;
	// en dado caso que requiera obtener todo el cuerpo del token, puede hacerlo con el atributo body.
	$body = $jwtCkeck->body;
}
else
{
	echo "Token no váido";
	print_r($jwtCkeck->errors);
}

```

## Creación de JWK, (JSON Web Token con firma)

En este caso se usan pares de llaves públicas y privadas para firmar el token,
permitiendo la distibución de la llave publica a diferentes receptores del token, esto
es muy útil cuando se tienen diferentes aplicativos de manera distribuida, los cuales
pueden validar los token sin tener la clave privada con la cuál se firmó el token.

La diferencia respecto a la implementación básica con JWT, es que para la generación se
usa otra clase y se pasa como key el contenido de la llave privada.

para la verificación se usa otra clase y como llave se pasa el contenido de la clave pública.

### Creación de JWK

En este caso, se especificará las diferencias de implementación, pero los claims e
identificador de llave se usan igual.

```php

use Hlmqz\JWT\JWKGenerator;

$privateKey = file_get_contents("pat/to/file/privateKey.pem");

$jwk = new JWKGenerator($privateKey);

```

### Vefificación de JWK

En este caso, se especificará las diferencias de implementación, pero los claims e
identificador de llave se usan igual.

teniendo en cuenta que puede cargar el token al crear el verificador, posterior
leer la referencia de la llave publica usada (que al crear el token se debió establecer)
y despues usar el contenido de la llave publica para validar.

```php

use Hlmqz\JWT\JWKChecker;

$jwkChecker = new JWKChecker($token, /*$publicKey*/);

$refPublic = $jwkChecker->keyIdentifier;

$publicKey = file_get_contents("pat/to/file/{$refPublic}.pem");

$jwkChecker->key = $publicKey;

```

### Funcionalidad de generar pares de llaves RSA

Este paquete también trae la funcionalidad de generar pares de llaves RSA pública y privada
para no depender, puede generarlas y guardarlas a necesidad.

```php

use Hlmqz\JWT\JWKGenerator;

// generar claves
$pair = JWKGenerator::newKeyPair();

$pair['privateKey']; //acceder al contenido de la llave privada.

$pair['publicKey']; //acceder al contenido de la llave pública.

// inclusive si ya tiene una llave privada, puede generar la publica con:

$publicKey = JWKGenerator::getPublicKey($privateKey);

```

Su implementación es sencilla, fácil de usar y sin dependencias innecesarias.

