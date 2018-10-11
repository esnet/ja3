##! Constants for the JA3 SSL hashing

module JA3;

export {
	## Additions to the Supported Groups Registry for GREASE.
	## For more info, see: https://tools.ietf.org/html/draft-davidben-tls-grease-01
	const grease: set[int] = {
		2570,
		6682,
		10794,
		14906,
		19018,
		23130,
		27242,
		31354,
		35466,
		39578,
		43690,
		47802,
		51914,
		56026,
		60138,
		64250
	};

	## The separator used between values of the same type for generating the hash.
	## Note: Changing this will break compatability with other implementations.
	## Default example: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
	const sep = "-";

	## The separator used between different types for generating the hash.
	## Note: Changing this will break compatability with other implementations.
	## Default example: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
    	const sep2 = ",";

}