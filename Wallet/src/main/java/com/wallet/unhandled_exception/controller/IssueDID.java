package com.wallet.unhandled_exception.controller;

import java.io.IOException;

import org.apache.commons.codec.DecoderException;
import org.apache.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.wallet.unhandled_exception.exceptions.Inaccurate;
import com.wallet.unhandled_exception.exceptions.NullExceptions;
import com.wallet.unhandled_exception.response.FinalResponse;
import com.wallet.unhandled_exception.response.Response;

import foundation.identity.jsonld.JsonLDException;
import lombok.NonNull;

@CrossOrigin
@RestController
@RequestMapping("/generate")
public class IssueDID {
	
	@RequestMapping(value = "/dids", consumes = {MediaType.APPLICATION_JSON_VALUE},
	        produces = {MediaType.APPLICATION_JSON_VALUE})
	public static FinalResponse generateDID(@RequestBody @NonNull String request) throws DecoderException, NullExceptions, IOException, Inaccurate, JsonLDException 
	{
//		try {
//			FinalResponse response = Response.genResponse(request);
//			
//		    response = DID_Doc_Repository.save(new FinalResponse(response.getDid_key(), response.getDid_web(), response.getDid_document()));
//		    return new ResponseEntity<>(response, HttpStatus.CREATED);
//		} 
//		catch (Exception e) {
//		    return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
//		  }
		return Response.genResponse(request);
	}	
}
