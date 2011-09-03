<?php
/*****************************
 *  PHP implementation of MultiPass encoding.
 *  Tom Vaughan
 *  http://rapidach.com
 *  9/2/2011
 *  Developed for use with Redmine MultiPass plugin to allow for Single Sign On (SSO). https://github.com/jozefvaclavik/redmine_multipass
 *  Code below is for encoding of user data that can be used to facilitate auto registration and auto login to Redmine.
 *  Links:
 * 	Redmine: http://redmine.org
 *      Remine MultiPass Gem: https://github.com/jozefvaclavik/redmine_multipass
 *****************************/

/*****************************
 *  Set params
 *****************************/

$site_key = 'site key here'; //best if these are in database
$api_key = 'api key here';
$firstname = 'Bob';
$lastname = 'Smith';
$email = 'bob.smith@bobsmith.com';
$date = new DateTime();
$date->add(new DateInterval('P1D'));
$expiry = $date->format('Y-m-d H:i:s'); //set expiration for 1 day from now
$uid = 2011; //this is whatever the unique id of the user is
// in case this is not obvious, it is best to generate a new link for a user every time they log into your main app 
//and have the link expire within the shortest amount of time.
/*****************************
 *  Auto Registration
 *****************************/

$reg_string = json_encode(array('site_key' => $site_key, 'api_key' => $api_key, 'first_name' => $firstname, 'last_name' => $lastname, 'email' => $email,
							   'remote_uid' => $uid, 'login' => $firstname . '.' . $lastname, 'expires' => $expiry . 'Z'));
$encoded_reg_string = gen_multipass($reg_string, $site_key, $api_key);

echo 'http://yourRedmineURL/multipass/?sso=' . $encoded_reg_string;
echo '<br>';
/*****************************
 *  Auto Login
 *****************************/

$login_string = json_encode(array('remote_uid' => $uid, 'expires' => $expiry . 'Z'));
$encoded_login_string = gen_multipass($login_string, $site_key, $api_key);

echo 'http://yourRedmineURL/multipass/?sso=' . $encoded_login_string;

function gen_multipass($data, $site_key, $api_key)
{
	$salted = $api_key . $site_key;
	$hash = hash('sha1', $salted, true);
	$saltedHash = substr($hash, 0, 16);
	$iv = "OpenSSL for Ruby";
	// double XOR first block
	for ($i = 0; $i < 16; $i++)
	{
		$data[$i] = $data[$i] ^ $iv[$i];
	}

	$pad = 16 - (strlen($data) % 16);
	$data = $data . str_repeat(chr($pad), $pad);

	$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', 'cbc', '');
	mcrypt_generic_init($cipher, $saltedHash, $iv);
	$encryptedData = mcrypt_generic($cipher, $data);
	mcrypt_generic_deinit($cipher);
	return urlencode(base64_encode($encryptedData));
}


