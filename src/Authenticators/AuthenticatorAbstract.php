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
use function in_array;
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
	 */
	public function __construct(array $options = null){

		if($options !== null){
			$this->setOptions($options);
		}

	}

	/**
	 * @inheritDoc
	 */
	public function setOptions(array $options):AuthenticatorInterface{

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
	public function setSecret(string $encodedSecret):AuthenticatorInterface{
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
	public function getSecret():string{

		if($this->secret === null){
			throw new RuntimeException('No secret set');
		}

		return Base32::encode($this->secret);
	}

	/**
	 * @inheritDoc
	 */
	public function createSecret(int $length = null):string{

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
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_algorithm(string $algorithm){
		$algorithm = strtoupper($algorithm);

		if(!in_array($algorithm, self::HASH_ALGOS, true)){
			throw new InvalidArgumentException('Invalid algorithm: '.$algorithm);
		}

		$this->algorithm = $algorithm;
	}

	/**
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_digits(int $digits){

		if(!in_array($digits, [6, 8], true)){
			throw new InvalidArgumentException('Invalid code length: '.$digits);
		}

		$this->digits = $digits;
	}

	/**
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_period(int $period){

		if($period < 15 || $period > 60){
			throw new InvalidArgumentException('Invalid period: '.$period);
		}

		$this->period = $period;
	}

	/**
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_secret_length(int $secret_length){
		// ~ 80 to 640 bits
		if($secret_length < 16 || $secret_length > 1024){
			throw new InvalidArgumentException('Invalid secret length: '.$secret_length);
		}

		$this->secret_length = $secret_length;
	}

	/**
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	protected function set_adjacent(int $adjacent){

		if($adjacent < 0){
			throw new InvalidArgumentException('Invalid adjacent value: '.$adjacent);
		}

		$this->adjacent = $adjacent;
	}

	/**
	 * @return void
	 */
	protected function set_time_offset(int $time_offset){
		$this->time_offset = $time_offset;
	}

}
