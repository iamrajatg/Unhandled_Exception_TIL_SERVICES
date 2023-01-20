package com.wallet.unhandled_exception.service;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;

public class Codec {
	public static byte[] decode(String publicKey) throws DecoderException
	{
		byte[] dec= Hex.decodeHex(publicKey.toCharArray());
		return dec;
	}	
	
	public static String multibase_encode(String publicKey) throws DecoderException
	{
		
		byte[] multicodecEncoding = Multicodec.encode(Multicodec.Codec.Ed25519PublicKey, decode(publicKey));
		String multibasePublicKey = Multibase.encode(Multibase.Algorithm.Base58Btc, multicodecEncoding);
		
		return multibasePublicKey;
	}
	
	public static byte[] multibase_decode(String publicKey) throws DecoderException
	{
		byte[] multicodecBytes = Multibase.decode(publicKey);
		byte[] decodedPublicKey = Multicodec.decode(Multicodec.Type.Key,multicodecBytes);
		
		return decodedPublicKey;
	}
}
