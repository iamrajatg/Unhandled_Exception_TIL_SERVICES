package com.wallet.unhandled_exception.service;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.wallet.unhandled_exception.model.DID_Doc;
import com.wallet.unhandled_exception.utility.FTPD;


public class FileEdit {
	
	private static final Logger logger = LoggerFactory.getLogger(FileEdit.class);  
	
	public static void uploadFTPD(String path, DID_Doc doc) throws IOException
	{		 
		Gson gson = new Gson();
		String json = gson.toJson(doc);
        FTPD.uploadFile(json, path);
		
		logger.info("Added public key to json file");
	}
//	
//	public static void del(String path)
//	{
//		Path path1 = Paths.get(path);
//		try {
//			Files.delete(path1);
//			return "Deleted!";
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
//		return "Can't delete. Check path.";
//	}
}
