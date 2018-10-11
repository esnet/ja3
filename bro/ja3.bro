# This Bro script appends JA3 to ssl.log
# Version 1.3 (June 2017)
#
# Authors: John B. Althouse (jalthouse@salesforce.com) & Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

@load ./consts
@load ./utils

module JA3;

# We store the data for the client here, until we generate the hash
type JA3_Client_Fields: record {
	client_version:  count &default=0 &log;
	client_ciphers:  string &default="" &log;
	extensions:      string &default="" &log;
	e_curves:        string &default="" &log;
	ec_point_fmt:    string &default="" &log;
};

# Add the fingerprint to the connection record.
redef record connection += {
       ja3: JA3_Client_Fields &optional;
}; 

# Add the field to the SSL log
redef record SSL::Info += {
	ja3: string &optional &log;
};

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	if ( ! c?$ja3 )
		c$ja3=JA3_Client_Fields();

	if ( is_orig )
		c$ja3$extensions = append_val(c$ja3$extensions, code);
	}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
	{
	if ( !c?$ja3 )
		c$ja3=JA3_Client_Fields();
		
    	if ( is_orig )
		{
        	for ( i in point_formats )
			{
			c$ja3$ec_point_fmt = append_val(c$ja3$ec_point_fmt, point_formats[i]);
        		}
    		}
	}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
	{
	if ( !c?$ja3 )
		c$ja3=JA3_Client_Fields();
		
    	if ( is_orig )
		{
        	for ( i in curves )
			{
			c$ja3$e_curves = append_val(c$ja3$e_curves_fmt, curves[i]);
        		}
    		}
	}

@if ( Version::at_least("2.6") )
event ssl_client_hello(c: connection, version: count, record_version:count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: vector of count) &priority=1
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=1
@endif
	{
	if ( !c?$ja3 )
		c$ja3=JA3_Client_Fields();
		
	c$ja3$client_version = version;
	
    	for ( i in ciphers )
		{
		c$ja3$ciphers = append_val(c$ja3$ciphers, ciphers[i]);
    		}
		
	local ja3_string = cat_sep(sep2, "", cat(c$ja3$client_version), c$ja3$client_ciphers, c$ja3$extensions, c$ja3$e_curves, c$ja3$ec_point_fmt);

    	c$ssl$ja3 = md5_hash(ja3_string);
	}
