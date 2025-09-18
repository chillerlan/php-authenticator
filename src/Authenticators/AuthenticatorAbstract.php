<?php
/**
 * Class AuthenticatorAbstract
 *
 * @created      25.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Authenticators;

use chillerlan\Authenticator\AuthenticatorOptions;
use chillerlan\Authenticator\Common\Base32;
use chillerlan\Settings\SettingsContainerInterface;
use InvalidArgumentException;
use RuntimeException;
use SensitiveParameter;
use function http_build_query;
use function random_bytes;
use function rawurlencode;
use function sprintf;
use function time;
use function trim;
use const PHP_QUERY_RFC3986;

/**
 *
 */
abstract class AuthenticatorAbstract implements AuthenticatorInterface{

	protected const userAgent = 'chillerlanAuthenticator/5.0 +https://github.com/chillerlan/php-authenticator';

	protected SettingsContainerInterface|AuthenticatorOptions $options;
	protected string|null                                     $secret          = null;
	protected int                                             $serverTime      = 0;
	protected int                                             $lastRequestTime = 0;

	/**
	 * AuthenticatorInterface constructor
	 */
	public function __construct(SettingsContainerInterface|AuthenticatorOptions $options = new AuthenticatorOptions){
		$this->setOptions($options);
	}

	/**
	 * @inheritDoc
	 */
	public function setOptions(SettingsContainerInterface $options):static{
		$this->options = $options;

		return $this;
	}

	/**
	 * @inheritDoc
	 */
	public function setSecret(#[SensitiveParameter] string $encodedSecret):static{
		$this->secret = Base32::decode($this->checkEncodedSecret($encodedSecret));

		return $this;
	}

	/**
	 * @inheritDoc
	 */
	public function getSecret():string{

		if($this->secret === null){
			throw new RuntimeException('No secret set');
		}

		return Base32::encode($this->secret);
	}

	/**
	 * @inheritDoc
	 */
	public function createSecret(int|null $length = null):string{
		$length ??= $this->options->secret_length;

		if($length < 16){
			throw new InvalidArgumentException('Invalid secret length: '.$length);
		}

		$this->secret = random_bytes($length);

		return $this->getSecret();
	}

	/**
	 * @inheritDoc
	 */
	public function getServertime():int{
		return time();
	}

	/**
	 * Get an adjusted time stamp for the given server time
	 */
	protected function getAdjustedTime(int $serverTime, int $lastRequestTime):int{
		$diff = (time() - $lastRequestTime);

		return ($serverTime + $diff);
	}

	/**
	 * Checks if the encoded secret is non-empty, returns the trimmed string on success
	 *
	 * @throws \InvalidArgumentException
	 */
	protected function checkEncodedSecret(string $encodedSecret):string{
		$encodedSecret = trim($encodedSecret);

		if($encodedSecret === ''){
			throw new InvalidArgumentException('The given secret string is empty');
		}

		return $encodedSecret;
	}

	/**
	 * Returns an array with settings for a mobile authenticator URI for the current authenticator mode/instance
	 */
	abstract protected function getUriParams(string $issuer, int|null $counter = null):array;

	/**
	 * @inheritDoc
	 */
	public function getUri(string $label, string $issuer, int|null $counter = null):string{
		$label  = trim($label);
		$issuer = trim($issuer);

		if($label === '' || $issuer === ''){
			throw new InvalidArgumentException('$label and $issuer cannot be empty');
		}

		return sprintf(
			'otpauth://%s/%s?%s',
			$this::MODE,
			rawurlencode($label),
			http_build_query($this->getUriParams($issuer, $counter), '', '&', PHP_QUERY_RFC3986),
		);
	}

}
