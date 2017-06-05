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
		Filename:		ipv4.class.php
		Purpose:		Function class for validating and manipulating IPv4 addresses
					and subnets
		Author:			Bas Roos <bas AT gatlan.nl>
		Version:		1.0
		Date:			20090521
		Language Version:	PHP 5
		Requirements:		-
		Comments:		-
	*/

	class IPv4 {

		// Function:		validate_ip
		// Purpose:		Validate an IPv4 address
		// Parameters:		String that needs to be verified
		// Return values:	true if valid, false if invalid

		function validate_ip($ip) {
			if (preg_match("/^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:[.](?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/", $ip))
				return true;
			else
				return false;
		} // function validate_ip


		// Function:		validate_subnet
		// Purpose:		Validate an IPv4 subnet (with notation address/CIDR)
		// Parameters:		String that needs to be verified
		// Return values:	true if valid, false if invalid

		function validate_subnet($subnet) {
			if (preg_match("/^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:[.](?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}\/(?:3[0-2]|[1-2]\d|\d)$/", $subnet))
				return true;
			else
				return false;
		} // function validate_subnet


		// Function:		validate_cidr
		// Purpose:		Validate an IPv4 CIDR (ranging from 0 to 32)
		// Parameters:		String (or integer) that needs to be verified
		// Return values:	true if valid, false if invalid

		function validate_cidr($cidr) {
			if (preg_match("/^(?:3[0-2]|[1-2]\d|\d)$/", $cidr))
				return true;
			else
				return false;
		} // function validate_cidr


		// Function:		iptohex
		// Purpose:		Transform a valid IPv4 address into a unsegmented hexadecimal
		//			string (ie. 192.168.52.4 -> c0a83404)
		// Parameters:		String with a valid IPv4 address
		// Return values:	hexadecimal IPv4 address, or false in case of an invalid IPv4 address

		function iptohex($ip) {
			if (!IPv4::validate_ip($ip))
				return false;

			$values = explode(".", $ip);

			foreach ($values as $index => $value)
				$values[$index] = sprintf("%02s", dechex($value));

			return implode("", $values);
		} // function iptohex


		// Function:		hextoip
		// Purpose:		Transform a unsegmented hexadecimal string into a valid IPv4
		//			address (ie. c0a83404 -> 192.168.52.4)
		// Parameters:		A unsegmented hexadecimal string
		// Return values:	Valid IPv4 address, or false in case of an invalid hexadecimal address

		function hextoip($hex) {
			if (!preg_match("/^[0-9a-fA-F]{0,8}$/", $hex))
				return false;
			
			$revhex = strrev($hex);
			$revchunks = str_split($revhex, 2);
			
			foreach ($revchunks as $index => $value)
				$revchunks[$index] = hexdec(strrev($value));

			while (count($revchunks) < 4)
				$revchunks[] = "0";

			$chunks = array_reverse($revchunks);

			return implode(".", array_reverse($revchunks));
		} // function hextoip


		// Function:		iptodec
		// Purpose:		Transform a valid IPv4 address into a decimal number
		// Parameters:		IPv4 address
		// Return values:	Decimal representation of the IPv4 address, or false in case of an invalid
		//			IPv4 address

		function iptodec($ip) {
			$hex = IPv4::iptohex($ip);

			return $hex ? hexdec($hex) : false;
		} // function iptodec


		// Function:		dectoip
		// Purpose:		Transform a decimal number into a IPv4 address
		// Parameters:		Decimal number (or string containing one)
		// Return values:	IPv4 address represented by the parameter, or false in case of an invalid
		//			decimal number

		function dectoip($dec) {
			if (!preg_match("/^[0-9]*$/", $dec))
				return false;
			return IPv4::hextoip(dechex($dec+0));
		} // function dectoip


		// Function:		cidrtomask
		// Purpose:		Calculate the subnet mask based on a CIDR
		// Parameters:		CIDR
		// Return values:	Subnet mask, or false in case of an invalid CIDR

		function cidrtomask($cidr) {
			if (!IPv4::validate_cidr($cidr))
				return false;

			return IPv4::dectoip(IPv4::iptodec("255.255.255.255")-(IPv4::cidrips($cidr)-1));
		} // function cidrtomask


		// Function:		cidrtowildcard
		// Purpose:		Calculate the wildcard address bassed on a CIDR
		// Parameters:		CIDR
		// Return values:	Wildcard address, or false in case of an invalid CIDR

		function cidrtowildcard($cidr) {
			if (!IPv4::validate_cidr($cidr))
				return false;

			return IPv4::dectoip((IPv4::cidrips($cidr)-1));
		} // function cidrtowildcard


		// Function:		cidrips
		// Purpose:		Calculate the number of IPv4 addresses in a CIDR
		// Parameters:		CIDR
		// Return values:	Decimal number of IPv4 addresses in given CIDR, of false in case of
		//			a invalid CIDR

		function cidrips($cidr) {
			if (!IPv4::validate_cidr($cidr))
				return false;

			return pow(2, (32-$cidr));
		} // function cidrips


		// Function:		minip
		// Purpose:		Calculate the lowest IPv4 address in a subnet
		// Parameters:		Subnet
		// Return values:	IPv4 address, or false in case of an invalid subnet

		function minip($subnet) {
			if (!IPv4::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);
			$ipcount = IPv4::cidrips($cidr);

			return IPv4::dectoip(IPv4::iptodec($ip)-(IPv4::iptodec($ip)%$ipcount));
		} // function minip


		// Function:		maxip
		// Purpose:		Calculate the highest IPv4 address in a subnet
		// Parameters:		Subnet
		// Return values:	IPv4 address, or false in case of an invalid subnet

		function maxip($subnet) {
			if (!IPv4::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);
			$ipcount = IPv4::cidrips($cidr);

			$minip = IPv4::minip($subnet);
			return IPv4::dectoip(IPv4::iptodec($minip)+$ipcount-1);
		} // function maxip


		// Function:		minhost
		// Purpose:		Calculate the lowest host IPv4 address in a subnet
		// Parameters:		Subnet
		// Return values:	IPv4 address, or false in case of an invalid subnet

		function minhost($subnet) {
			if (!IPv4::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);

			$minip = IPv4::minip($subnet);
			
			return IPv4::dectoip(IPv4::iptodec($minip)+($cidr < 31 ? 1 : 0));
		} // function minhost


		// Function:		maxhost
		// Purpose:		Calculate the highest host IPv4 address in a subnet
		// Parameters:		Subnet
		// Return values:	IPv4 address, or false in case of an invalid subnet

		function maxhost($subnet) {
			if (!IPv4::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);

			$maxip = IPv4::maxip($subnet);
			return IPv4::dectoip(IPv4::iptodec($maxip)-($cidr < 31 ? 1 : 0));
		} // function maxhost


		// Function:		calc
		// Purpose:		ipcalc-like function that returns an array with various
		//			information about a given subnet
		// Parameters:		IPv4 subnet
		// Return values:	Associative array with;
		//			address - IPv4 address in the subnet
		//			netmask - Netmask of the subnet
		//			wildcard - Wildcard representation oft he subnet
		//			network - Lowest IPv4 address of the subnet, follow by /CIDR
		//			minip - Lowest IPv4 address of the subnet
		//			maxip - Highest IPv4 address of the subnet
		//			minhost - Lowest host IPv4 address of the subnet
		//			maxhost - Highest host IPv4 address of the subnet
		//			ipcount - Number of IPv4 addresses in the subnet
		//			hostcount - Number of hosts in the subnet

		function calc($subnet) {
			if (!IPv4::validate_subnet($subnet))
				return false;

			list($ip, $cidr) = explode("/", $subnet);
			
			$ipcount = IPv4::cidrips($cidr);
			$minip = IPv4::minip($subnet);

			return array(	"address"	=> $ip
				,	"netmask"	=> IPv4::cidrtomask($cidr)
				,	"wildcard"	=> IPv4::cidrtowildcard($cidr)
				,	"network"	=> $minip ."/" .$cidr
				,	"minip"		=> $minip
				,	"maxip"		=> IPv4::maxip($subnet)
				,	"minhost"	=> IPv4::minhost($subnet)
				,	"maxhost"	=> IPv4::maxhost($subnet)
				,	"ipcount"	=> $ipcount
				,	"hostcount"	=> ($ipcount > 2 ? ($ipcount-2) : $ipcount)
				);
		} // function calc

	} // class IPv4
?>
