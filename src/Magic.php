<?php
/**
 * Trait Magic
 *
 * @filesource   Magic.php
 * @created      25.10.2017
 * @package      chillerlan\GoogleAuth
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2017 Smiley
 * @license      MIT
 */

namespace chillerlan\GoogleAuth;

trait Magic{

	/**
	 * @param string $property
	 *
	 * @return null
	 */
	public function __get(string $property){

		if(property_exists($this, $property)){
			return $this->{$property};
		}

		return null; // @codeCoverageIgnore
	}

	/**
	 * @param string $property
	 * @param mixed  $value
	 */
	public function __set(string $property, $value){
		$method = 'set'.ucfirst($property);

		if(method_exists($this, $method)){
			$this->{$method}($value);
		}

	}

}
