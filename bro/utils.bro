# Helpful utilities for JA3 and JA3S

module JA3;

@load ./consts

function append_val(current: string, new_val: count): string
	{
	if ( new_val in grease )
		return current;

	if ( current == "" )
		return cat(new_val);

	return cat_sep(sep, "", current, cat(new_val));
	}

