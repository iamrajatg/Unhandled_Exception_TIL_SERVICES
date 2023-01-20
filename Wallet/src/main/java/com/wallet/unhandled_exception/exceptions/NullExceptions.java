package com.wallet.unhandled_exception.exceptions;

public class NullExceptions extends Exception {
	public NullExceptions()
	{
		throw new NullPointerException();
	}
}
