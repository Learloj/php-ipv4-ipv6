<?
	/*
		Copyright (c) 2009 - Bas Roos <bas AT gatlan.nl>

		All Rights Reserved

		Permission to use, copy, modify, and distribute this software and its
		documentation for any purpose and without fee is hereby granted,
		provided that the above copyright notice appear in all copies and that
		both that copyright notice and this permission notice appear in
		supporting documentation, and that the name of the author not be
		used in advertising or publicity pertaining to distribution of the
		software without specific, written prior permission.

		THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
		ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
		AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
		DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
		AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
		OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
	*/

	/*
		Filename:		ipv6.class.php
		Purpose:		Function class for validating and manipulating IPv6 addresses
					and subnets
		Author:			Bas Roos <bas AT gatlan.nl>
		Version:		1.0
		Date:			20090521
		Language Version:	PHP 5
		Requirements:		ipv4.class.php v1.0
		Comments:		-
	*/

	require_once("ipv4.class.php");

	class IPv6 {

		// Function:		uncompress
		// Purpose:		Uncompress an IPv6 address
		//			ie. 2001:db8::1 => 2001:0db8:0000:0000:0000:0000:0000:0001
		// Parameters:		IPv6 address
		// Return values:	Uncompressed IPv6 address, or false in case of an invalid IPv6 address

		function uncompress($ip) {
			if (!($type = IPv6::validate_ip($ip)))
				return false;

			// Add additional colon's, until 7 (or 6 in case of an IPv4 (mapped) address
			while (substr_count($ip, ":") < (substr_count($ip, ".") == 3 ? 6 : 7))
				$ip = substr_replace($ip, "::", strpos($ip, "::"), 1);

			$ip = explode(":", $ip);

			// Replace the IPv4 address with hexadecimals if needed
			if (in_array($type, array("ipv4", "ipv4_mapped"))) {
				$ipv4 = $ip[count($ip)-1];
				$ipv4hex = IPv4::iptohex($ipv4);
				$hex = sprintf("%08s", IPv4::iptohex($ipv4));
				$ip[count($ip)-1] = substr($hex, 0, 4);
				$ip[] = substr($hex, 4, 4);
			}

			// Add leading 0's in every part, up until 4 characters
			foreach ($ip as $index => $part)
				$ip[$index] = sprintf("%04s", $part);

			return implode(":", $ip);
		} // function uncompress


		// Function:		compress
		// Purpose:		Compress an IPv6 address, according to 
		//			http://tools.ietf.org/html/draft-kawamura-ipv6-text-representation-02
		//			ie. 2001:0db8:0000:0000:0000:0000:0000:0001 => 2001:db8::1
		// Parameters		IPv6 address
		// Return values:	Compressed IPv6 address, or false in case of an invalid IPv6 address

		function compress($ip) {
			if (!IPv6::validate_ip($ip))
				return false;

			// Uncompress the address, so we are sure the address isn't already compressed
			$ip = IPv6::uncompress($ip);

			// Remove all leading 0's; 0034 -> 34; 0000 -> 0
			$ip = preg_replace("/(^|:)0+(?=[a-fA-F\d]+(?::|$))/", "$1", $ip);

			// Find all :0:0: sequences
			preg_match_all("/((?:^|:)0(?::0)+(?::|$))/", $ip, $matches);

			// Search all :0:0: sequences and determine the longest
			$reg = "";
			foreach ($matches[0] as $match)
				if (strlen($match) > strlen($reg))
					$reg = $match;

			// Replace the longst :0 sequence with ::, but do it only once
			if (strlen($reg))
				$ip = preg_replace("/$reg/", "::", $ip, 1);

			return $ip;
		} // function compress

		
		// Function:		validate_ip
		// Purpose:		Validate an IPv6 address and determine the type
		// Parameters:		IPv6 address
		// Return values:	IPv6 address type (preferred, compressed, ipv4 or ipv4_mapped)
		//			or false in case of an invalid IPv6 address

		function validate_ip($ip) {
			// Define all IPv6 address types
			$ipv6regexes = array(
				"preferred" => array(
					"/^(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}$/i"
				),
				"compressed" => array(
					"/^[a-f0-9]{0,4}::$/i",
					"/^:(?::[a-f0-9]{1,4}){1,6}$/i",
					"/^(?:[a-f0-9]{1,4}:){1,6}:$/i",
					"/^(?:[a-f0-9]{1,4}:)(?::[a-f0-9]{1,4}){1,6}$/i",
					"/^(?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}$/i",
					"/^(?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}$/i",
					"/^(?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}$/i",
					"/^(?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}$/i",
					"/^(?:[a-f0-9]{1,4}:){6}(?::[a-f0-9]{1,4})$/i"
				),
				"ipv4" => array(
					"/^::(?:\d{1,3}\.){3}\d{1,3}$/",
					"/^(?:0:){6}(?:\d{1,3}\.){3}\d{1,3}$/i"
				),
				"ipv4_mapped" => array(
					"/^(?:0:){5}ffff:(?:\d{1,3}\.){3}\d{1,3}$/i",
					"/^::ffff:(?:\d{1,3}\.){3}\d{1,3}$/"
				)
			);
			// Search the address types and return the name if it matches
			foreach ($ipv6regexes as $type => $regexes) {
				foreach ($regexes as $regex)
					if (preg_match($regex, $ip)) {
						if (in_array($type, array("ipv4", "ipv4_mapped"))) {
							$ipparts = explode(":", $ip);
							$ipv4part = $ipparts[count($ipparts)-1];
							if (IPv4::validate_ip($ipv4part))
								return $type;
						} else
							return $type;
					}
			}

			// Return false if we didn't match an address type
			return false;
		} // function validate_ip


		// Function: 		validate_subnet
		// Purpose:		Validate a IPv6 subnet
		// Parameters:		IPv6 subnet in the form of IPv6/CIDR
		// Return values:	true if valid, false if invalid

		function validate_subnet($subnet) {
			$parts = explode("/", $subnet);
			if (count($parts) != 2)
				return false;

			if (!IPv6::validate_ip($parts[0]) || !IPv6::validate_cidr($parts[1]))
				return false;
			else
				return true;
		} // function validate_subnet

		// Function:		validate_cidr
		// Purpose:		Validate a IPv6 CIDR
		// Parameters:		CIDR
		// Return values:	true if valid (0-128), false if invalid
		function validate_cidr($cidr) {
			if (preg_match("/^(?:12[0-8]|1[0-1]\d|\d\d|\d)$/", $cidr))
				return true;
			else
				return false;
		}

		// Function:		iptobin
		// Purpose:		Transform a IPv6 address to bit-notation
		//			ie. 2001:0db8:: => 00100000000000010000110110111000... (etc.)
		// Parameters:		IPv6 address
		// Return values:	String with bit-notation of the IPv6 address, or false in case
		//			of an invalid IPv6 address

		function iptobin($ip) {
			if (!($type = IPv6::validate_ip($ip)))
				return false;

			$ip = IPv6::uncompress($ip);
			$ip = explode(":", $ip);

			$binip = "";
			foreach ($ip as $value)
				$binip .= sprintf("%016s", decbin(hexdec($value)));

			return $binip;
		} // function iptobin


		// Function:		bintoip
		// Purpose		Transform a bit-notation to an IPv6 address
		//			ie. 00100000000000010000110110111000... (etc.) => 2001:0db8:0000:... (etc.)
		// Parameters:		String with bits (0's and 1's)
		// Return values:	Uncompressed IPv6 address, or false in case of an invalid parameter

		function bintoip($ip) {
			if (!preg_match("/^[0-1]{0,128}$/", $ip))
				return false;

			$ip = sprintf("%0128s", $ip);

			$ip = str_split($ip, 4);
			foreach ($ip as $index => $value)
				$ip[$index] = dechex(bindec($value));

			return implode(":", str_split(implode("", $ip), 4));
		} // function bintoip


		// Function:		cidrips
		// Purpose:		Calculate the number of IPv6 addresses in a CIDR
		// Parameters:		CIDR
		// Return value:	Integer or float with the number of IPv6 addresses in the given CID

		function cidrips($cidr) {
			if (!IPv6::validate_cidr($cidr))
				return false;

			return pow(2, (128-$cidr));
		} // function cidrips


		// Function:		minip
		// Purpose:		Calculate the lowest IP address in a subnet
		// Parameters:		IPv6 subnet
		// Return values:	Uncompressed IPv6 address, or false in case of an invalid subnet

		function minip($subnet) {
			if (!IPv6::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);

			return IPv6::bintoip(substr(IPv6::iptobin($ip), 0, $cidr) . sprintf("%0" .(128-$cidr) ."s", ""));
		} //function minip


		// Function:		maxip
		// Purpose:		Calculate the highest IP address in a subnet
		// Parameters:		IPv6 subnet
		// Return values:	Uncompressed IPv6 address, or false in case of an invalid subnet

		function maxip($subnet) {
			if (!IPv6::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);

			return IPv6::bintoip(substr(IPv6::iptobin($ip), 0, $cidr) . sprintf("%'1" .(128-$cidr) ."s", ""));
		} // function maxip

		
		// Function:		get_next
		// Purpose:		Calculate the IP address that comes after given IP address
		//			ie. 2001:db8::1 => (uncompressed version of) 2001:db8::2
		// Parameters		IPv6 address
		// Return values:	Uncompressed IPv6 address

		function get_next($ip) {
			if (IPv6::validate_subnet($ip)) {
				list($ip, $cidr) = explode("/", $ip);
				return IPv6::get_next(IPv6::maxip($ip ."/" .$cidr)) ."/" .$cidr;
			} else if (IPv6::validate_ip($ip)) {
				$binip = IPv6::iptobin($ip);
				if ($binip == sprintf("%'1", 128))
					return false;
				else {
					$bits = str_split($binip);
					for ($index = count($bits)-1; $index >= 0; $index--) {
						if ($bits[$index] == 1)
							$bits[$index] = 0;
						else {
							$bits[$index] = 1;
							break;
						}
					}
					return IPv6::bintoip(implode("", $bits));
				}
			} else
				return false;
		}


		// Function:		calc
		// Purpose:		ipcalc like function that returns an array of information about
		//			the given IPv6 subnet
		// Parameters:		IPv6 subnet
		// Return values:	Associative array with;
		//			address - IPv6 address of the IPv6 subnet
		//			cidr - CIDR of the subnet
		//			uncompress - Uncompressed version of the IPv6 address
		//			compress - Compressed version of the IPv6 address
		//			network - Network address of the IPv6 subnet
		//			minip - Lowest IPv6 address in the IPv6 subnet
		//			maxip - Highest IPv6 address in the IPv6 subnet
		//			ipcount - Number of IPv6 addresses in the IPv6 subnet

		function calc($subnet) {
			if (!IPv6::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);

			$minip = IPv6::minip($subnet);

			return array(	"address"	=> $ip
				,	"cidr"		=> $cidr
				,	"uncompress"	=> IPv6::uncompress($ip)
				,	"compress"	=> IPv6::compress($ip)
				,	"network"	=> $minip ."/" .$cidr
				,	"minip"		=> $minip
				,	"maxip"		=> IPv6::maxip($subnet)
				,	"ipcount"	=> IPv6::cidrips($cidr)
				);
		} // function calc

	} // class IPv6
?>
