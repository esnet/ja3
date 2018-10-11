## Helpful utilities for JA3 and JA3S

function append_option(current: string, new_val: count): string
	{
	if ( new_val in grease )
		return current;

	if ( current == "" )
		return cat(new_val);

	return cat_sep(sep, "", current, cat(new_val));
	}

