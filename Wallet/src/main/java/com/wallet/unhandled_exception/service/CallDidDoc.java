package com.wallet.unhandled_exception.service;

import org.springframework.web.client.RestTemplate;

import com.wallet.unhandled_exception.response.FinalResponse;

public class CallDidDoc {
	
	static final String uri = "http://localhost:9999/hackandhustle23/unhandledexception/generate/dids";
	
	public static FinalResponse getDidDoc()
	{
		RestTemplate restTemplate = new RestTemplate();
		FinalResponse res = restTemplate.getForObject(uri, FinalResponse.class);
		
		return res;
	}
}
