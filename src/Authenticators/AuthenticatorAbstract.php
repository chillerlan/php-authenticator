<?php
/**
 * Class AuthenticatorAbstract
 *
 * @created      25.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator\Authenticators;

use chillerlan\Authenticator\Common\Base32;
use InvalidArgumentException;
use RuntimeException;
use TypeError;
use function in_array;
use function is_int;
use function is_string;
use function property_exists;
use function random_bytes;
use function strtoupper;
use function trim;

/**
 *
 */
abstract class AuthenticatorAbstract implements AuthenticatorInterface{

	/** @var string */
	protected $algorithm = AuthenticatorInterface::ALGO_SHA1;

	/** @var int */
	protected $digits = 6;

	/** @var int */
	protected $period = 30;

	/** @var int */
	protected $secret_length = 20;

	/** @var int */
	protected $adjacent = 1;

	/** @var int */
	protected $time_offset = 0;

	/** @var string|null */
	protected $secret = null;

	/**
	 * AuthenticatorInterface constructor
	 *
	 * @param array|null $options
	 */
	public function __construct(array $options = null){

		if($options !== null){
			$this->setOptions($options);
		}

	}

	/**
	 * @inheritDoc
	 */
	public function setOptions(array $options){

		foreach($options as $property => $value){
			// skip non-existing props
			if(!property_exists($this, $property) || $property === 'secret'){
				continue;
			}

			// call the setter
			$this->{'set_'.$property}($value);
		}

		return $this;
	}

	/**
	 * @inheritDoc
	 */
	public function setSecret($encodedSecret){

		if(!is_string($encodedSecret)){
			throw new TypeError('$encodedSecret is expected to be string'); // @codeCoverageIgnore
		}

		$encodedSecret = trim($encodedSecret);

		if($encodedSecret === ''){
			throw new InvalidArgumentException('The given secret string is empty');
		}

		$this->secret = Base32::decode($encodedSecret);

		return $this;
	}

	/**
	 * @inheritDoc
	 */
	public function getSecret(){

		if($this->secret === null){
			throw new RuntimeException('No secret set');
		}

		return Base32::encode($this->secret);
	}

	/**
	 * @inheritDoc
	 */
	public function createSecret($length = null){

		if($length === null){
			$length = $this->secret_length;
		}

		if($length < 16){
			throw new InvalidArgumentException('Invalid secret length: '.$length);
		}

		$this->secret = random_bytes($length);

		return $this->getSecret();
	}

	/**
	 * @param string $algorithm
	 *
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_algorithm($algorithm){

		if(!is_string($algorithm)){
			throw new TypeError('$algorithm is expected to be string'); // @codeCoverageIgnore
		}

		$algorithm = strtoupper($algorithm);

		if(!in_array($algorithm, self::HASH_ALGOS, true)){
			throw new InvalidArgumentException('Invalid algorithm: '.$algorithm);
		}

		$this->algorithm = $algorithm;
	}

	/**
	 * @param int $digits
	 *
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_digits($digits){

		if(!is_int($digits)){
			throw new TypeError('$digits is expected to be int'); // @codeCoverageIgnore
		}

		if(!in_array($digits, [6, 8], true)){
			throw new InvalidArgumentException('Invalid code length: '.$digits);
		}

		$this->digits = $digits;
	}

	/**
	 * @param int $period
	 *
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_period($period){

		if(!is_int($period)){
			throw new TypeError('$period is expected to be int'); // @codeCoverageIgnore
		}

		if($period < 15 || $period > 60){
			throw new InvalidArgumentException('Invalid period: '.$period);
		}

		$this->period = $period;
	}

	/**
	 * @param int $secret_length
	 *
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_secret_length($secret_length){

		if(!is_int($secret_length)){
			throw new TypeError('$secret_length is expected to be int'); // @codeCoverageIgnore
		}

		// ~ 80 to 640 bits
		if($secret_length < 16 || $secret_length > 1024){
			throw new InvalidArgumentException('Invalid secret length: '.$secret_length);
		}

		$this->secret_length = $secret_length;
	}

	/**
	 * @param $adjacent
	 *
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_adjacent($adjacent){

		if(!is_int($adjacent)){
			throw new TypeError('$adjacent is expected to be int'); // @codeCoverageIgnore
		}

		if($adjacent < 0){
			throw new InvalidArgumentException('Invalid adjacent value: '.$adjacent);
		}

		$this->adjacent = $adjacent;
	}

	/**
	 * @param $time_offset
	 *
	 * @return void
	 */
	protected function set_time_offset($time_offset){

		if(!is_int($time_offset)){
			throw new TypeError('$time_offset is expected to be int'); // @codeCoverageIgnore
		}

		$this->time_offset = $time_offset;
	}

}
