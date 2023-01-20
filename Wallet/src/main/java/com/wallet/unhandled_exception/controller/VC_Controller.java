package com.wallet.unhandled_exception.controller;

import java.io.IOException;

import org.apache.commons.codec.DecoderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vc.unhandled_exception.model.VerifyResponse;
import com.wallet.unhandled_exception.exceptions.Inaccurate;
import com.wallet.unhandled_exception.exceptions.NullExceptions;
import com.wallet.unhandled_exception.response.FinalResponse;
import com.wallet.unhandled_exception.response.VC_Issue_Verify;
import com.wallet.unhandled_exception.service.CallDidDoc;

import foundation.identity.jsonld.JsonLDException;
import lombok.NonNull;

@CrossOrigin
@RestController
@RequestMapping("/vc")
public class VC_Controller {
	
	@PostMapping(value = "/issue", consumes = {MediaType.APPLICATION_JSON_VALUE},
	        produces = {MediaType.APPLICATION_JSON_VALUE})
	public static String issueDID(@RequestBody @NonNull String request) throws DecoderException, NullExceptions, IOException, Inaccurate, JsonLDException 
	{	
//		finalResponse = CallDidDoc.getDidDoc();
		return VC_Issue_Verify.issueVC(request);
	}
	
	@PostMapping(value = "/verify", consumes = {MediaType.APPLICATION_JSON_VALUE},
	        produces = {MediaType.APPLICATION_JSON_VALUE})
	public static VerifyResponse verifyDID(@RequestBody @NonNull String request) throws DecoderException, NullExceptions, IOException, Inaccurate, JsonLDException 
	{
//		finalResponse = CallDidDoc.getDidDoc();
		return VC_Issue_Verify.verifyVC(request);
	}
}
