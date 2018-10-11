# This Bro script appends JA3S (JA3 Server) to ssl.log
# Version 1.0 (August 2018)
# This builds a fingerprint for the SSL Server Hello packet based on SSL/TLS version, cipher picked, and extensions used. 
# Designed to be used in conjunction with JA3 to fingerprint SSL communication between clients and servers.
#
# Authors: John B. Althouse (jalthouse@salesforce.com) Jeff Atkinson (jatkinson@salesforce.com)
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

@load ./consts

module JA3;


# We store the data for the server here, until we generate the hash
type JA3_Server_Fields: record {
	server_version:     count &default=0 &log;
	server_cipher:      count &default=0 &log;
	server_extensions:  string &default="" &log;
};


# Add the fingerprint to the connection record.
redef record connection += {
	ja3s: JA3_Server_Fields &optional;
};

# Add the field to the SSL log
redef record SSL::Info += {
	ja3s: string &optional &log;
};


event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	if ( !c?$ja3s )
		c$ja3s=JA3_Server_Fields();

	if ( !is_orig )
		c$ja3s$server_extensions = append_val(c$ja3s$server_extensions, code);
	}

@if ( Version::at_least("2.6") )
event ssl_client_hello(c: connection, version: count, record_version:count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: vector of count) &priority=1
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=1
@endif
	{
	if ( !c?$ja3s )
		c$ja3s=JA3_Server_Fields();

	c$ja3s$server_version = version;
	c$ja3s$server_cipher = cipher;

	local ja3s_string = cat_sep(sep2, "", cat(c$ja3s$server_version), cat(c$ja3s$server_cipher), c$ja3s$server_extensions);

	c$ssl$ja3s = md5_hash(ja3s_string);
	}