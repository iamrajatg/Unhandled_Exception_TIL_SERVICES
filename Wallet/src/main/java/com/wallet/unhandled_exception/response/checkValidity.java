package com.wallet.unhandled_exception.response;

import com.google.gson.JsonElement;

public class checkValidity {
	public static Boolean isValid(String request)
	{
		if(request == null || request.isEmpty() || request.isBlank() || request == "\"\"") 
			return false;
		return true;
	}
	
	public static Boolean isVal(JsonElement request)
	{
		if(request.isJsonNull())
			return false;
		return true;
	}
	
	public static Boolean isStringValid(String request)
	{
		if(request == null || request.isEmpty())
			return false;
		return true;
	}
}
