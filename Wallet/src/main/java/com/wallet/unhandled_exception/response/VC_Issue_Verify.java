package com.wallet.unhandled_exception.response;

import java.io.FileReader;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.shaded.json.parser.JSONParser;
import com.vc.unhandled_exception.encryption.Base58;
import com.vc.unhandled_exception.model.VerifyResponse;
import com.vc.unhandled_exception.service.Issue_Verify;
import com.wallet.unhandled_exception.exceptions.NullExceptions;
import com.wallet.unhandled_exception.service.Codec;
import com.wallet.unhandled_exception.service.Conversion;
import com.wallet.unhandled_exception.service.CreateDIDWeb;
import com.wallet.unhandled_exception.utility.FTPD;

public class VC_Issue_Verify {
	
	private static final Logger logger = LoggerFactory.getLogger(VC_Issue_Verify.class);
	
	static final String PRIVATE_KEY = "4cf8394de5f8fc66301aac3bfe13c1778cd922323827499096ad5e717297fc8267f270bad09157546f658ef2eeda8c9e5f0fffaf9a0a616a3f73b3c7683ecee7";
	static final String PUBLIC_KEY = "67f270bad09157546f658ef2eeda8c9e5f0fffaf9a0a616a3f73b3c7683ecee7";
	
	public static JsonObject convertToJsonObject(String request)
	{
		Gson gson = new Gson();
		JsonElement element = gson.fromJson(request, JsonElement.class);
		JsonObject jsonObj = element.getAsJsonObject();
		
		return jsonObj;
	}
	
	public static String readJsonforWeb(String location)
	{
		JSONParser parser = new JSONParser();
	      try {
	    	 String publicKeyJson, publicKeyBase58;
	         Object obj = parser.parse(new FileReader(location));
	         JSONObject jsonObject = (JSONObject)obj;
	         publicKeyJson = jsonObject.get("publickey").toString();
	         JsonObject jsonObj = convertToJsonObject(publicKeyJson);
	         publicKeyBase58 = jsonObj.get("publicKeyBase58").toString();			
	         publicKeyBase58 =  Conversion.toString(publicKeyBase58);
	         
	         return publicKeyBase58;             
	      } 
	      catch(Exception e) {
	    	  logger.error("Public Key could not be found for DID WEB", e.getMessage(),
						e);
	      }
	      return null;
	}
	
	public static String getPublicKeyfromWeb(String uri)
	{
		FTPD.download(uri);		
		return readJsonforWeb("D:/Downloads/did.json");
	}
	
	public static byte[] getPublicKeyfromDoc(FinalResponse res)
	{
		byte[] publickey = new byte[32];
		String didpublickeyBase58 = res.getDid_key();			
		if(StringUtils.isEmpty(didpublickeyBase58))			
		{
			didpublickeyBase58 = res.getDid_web();	
			String uri = CreateDIDWeb.read(didpublickeyBase58);
			didpublickeyBase58 = getPublicKeyfromWeb(uri);
			publickey = Base58.decode(didpublickeyBase58);
		}
		else
		{
			didpublickeyBase58 = didpublickeyBase58.replaceAll("did:key:", "");				
			
			try {
				publickey = Codec.multibase_decode(didpublickeyBase58);
			} 
			catch (DecoderException e) {
				logger.error("Could not decode the public key from DID KEY", e.getMessage(),
						e);
			}
		}
		
		return publickey;
	}
	
	@SuppressWarnings("unchecked")
	public static String issueVC(String request)
	{		
		JsonObject jsonObj = convertToJsonObject(request);
		try {
			String subjectDID, issuerDID, duration, type, claimsJsonString;
			byte[] didpublickey = new byte[32];
			//didpublickey = getPublicKeyfromDoc(res);
			Integer dura;			
			
			claimsJsonString = jsonObj.get("claims").toString();				
			Map<String, Object> claims = new HashMap<String, Object>();
			ObjectMapper mapper = new ObjectMapper();
			claims =  mapper.readValue(claimsJsonString, Map.class);						
			
			subjectDID = jsonObj.get("subjectDID").toString();			
			subjectDID =  Conversion.toString(subjectDID);		
			
			issuerDID = jsonObj.get("issuerDID").toString();			
			issuerDID =  Conversion.toString(issuerDID);
			
			duration = jsonObj.get("duration").toString();			
			duration =  Conversion.toString(duration);
			dura = Integer.parseInt(duration);			
			
			type = jsonObj.get("type").toString();			
			type =  Conversion.toString(type);
					
			if(StringUtils.isEmpty(claimsJsonString) || StringUtils.isEmpty(subjectDID) 
					|| StringUtils.isEmpty(issuerDID) || StringUtils.isEmpty(duration) || StringUtils.isEmpty(type)) 				
				throw new NullExceptions();
			
			Date t1 =  Calendar.getInstance().getTime();
			String vc = Issue_Verify.issueVC(claims, PRIVATE_KEY, subjectDID, issuerDID, dura, type);
			
			logger.info("TIME TAKEN by sdk to issue VC in ms: {}",
					Calendar.getInstance().getTime().getTime() - t1.getTime());
			
			return vc;
		}
		catch(NullPointerException e)
		{			
			logger.error("Error as value entered is null with message", e.getMessage(),
							e);
		}
		catch(Exception e){
			logger.error("Error with message", e.getMessage(),
					e);
		}
				
		return null;
	}
	
	public static com.vc.unhandled_exception.model.VerifyResponse verifyVC(String request)
	{
		JsonObject jsonObj = convertToJsonObject(request);		
		
		try {
			String credential;
			byte[] didpublickey = new byte[32];;				
			//didpublickey = getPublicKeyfromDoc(res);
			
			credential = jsonObj.get("credential").toString();			
			//credential =  Conversion.toString(credential);
			
			if(StringUtils.isEmpty(credential)) 				
				throw new NullExceptions();	
			
			Date t1 = Calendar.getInstance().getTime();
			com.vc.unhandled_exception.model.VerifyResponse verify = null;
			verify = Issue_Verify.verifyVC(credential);	
			
			logger.info("TIME TAKEN by sdk to verify VC in ms: {}",
					Calendar.getInstance().getTime().getTime() - t1.getTime());
			
			return verify;
		}
		catch(NullPointerException e)
		{
			logger.error("Error  as value entered is null with message", e.getMessage(),
							e);
		}
		catch(Exception e){
			logger.error("Error with message", e.getMessage(),
					e);
		}
				
		return null;
	}
}
