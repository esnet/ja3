# This Bro script appends JA3 to ssl.log
# Version 1.4 (October 2018)
#
# Original authors: John B. Althouse (jalthouse@salesforce.com) & Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

@load ./consts

module JA3;

type TLSFPStorage: record {
	client_version:  count &default=0 &log;
	client_ciphers:  string &default="" &log;
	extensions:      string &default="" &log;
	e_curves:        string &default="" &log;
	ec_point_fmt:    string &default="" &log;
};

# Add the fingerprint to the connection record.
redef record connection += {
       tlsfp: TLSFPStorage &optional;
}; 

# Add the field to the SSL log
redef record SSL::Info += {
	ja3:            string &optional &log;
};

function append_option(current: string, new_val: count): string
	{
	if ( val in grease )
		return current;

	if ( current == "" )
		return cat(new_val);

	return cat_sep(sep, "", current, cat(new_val));
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	if ( ! c?$tlsfp )
    		c$tlsfp=TLSFPStorage();

	if ( is_orig )
		c$tlsfp$extensions = append_val(c$tlsfp$extensions, code);
	}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
	{
	if ( !c?$tlsfp )
    		c$tlsfp=TLSFPStorage();
		
    	if ( is_orig )
		{
        	for ( i in point_formats )
			{
			c$tlsfp$ec_point_fmt = append_val(c$tlsfp$ec_point_fmt, point_formats[i]);
        		}
    		}
	}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
	{
    	if ( !c?$tlsfp )
    		c$tlsfp=TLSFPStorage();
		
    	if ( is_orig )
		{
        	for ( i in curves )
			{
			c$tlsfp$e_curves = append_val(c$tlsfp$e_curves_fmt, curves[i]);
        		}
    		}
	}

@if ( Version::at_least("2.6") )
event ssl_client_hello(c: connection, version: count, record_version:count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: vector of count) &priority=1
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=1
@endif
	{
	if ( !c?$tlsfp )
    		c$tlsfp=TLSFPStorage();
		
    	c$tlsfp$client_version = version;
	
    	for ( i in ciphers )
		{
		c$tlsfp$ciphers = append_val(c$tlsfp$ciphers, ciphers[i]);
    		}
		
    	local ja3_string = cat_sep(sep2, "", cat(c$tlsfp$client_version), c$tlsfp$client_ciphers, c$tlsfp$extensions, c$tlsfp$e_curves, c$tlsfp$ec_point_fmt);

    	c$ssl$ja3 = md5_hash(ja3_string);
}
