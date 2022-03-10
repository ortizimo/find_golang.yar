import "hash"

rule find_golang
{					
	meta:
		author = "Saulo 'Sal' Ortiz, Sr. Cyber Forensics Analyst, ATG"
		description = "Searches for GoLang Fake Malware used against Ukraine"
		date = "2022-03-08"
		version = "1.0"
		in_the_wild = "True"
						
	strings:
		$a1 = {FF 20 47 6F 20 62} private			// @ offset 0x600
									
	condition:
		$a1
		or hash.md5(0, filesize) == "d5d2c4ac6c724cd63b69ca054713e278"
}
