package com.pingidentity.refreshtokendemo.tokenmgt.pingdirectory.utilities;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

public class KeyStoreCreator {
	
	public static KeyStore getKeyStore(String keystorePass, String pkFileName, String [] certFiles) throws Exception
	{		
		return getKeyStore(keystorePass, pkFileName, certFiles, "JKS");
		
	}
	
	public static KeyStore getKeyStore(String keystorePass, String pkFileName, String [] certFiles, String keystoreType) throws Exception
	{		
		KeyStore keystore = KeyStore.getInstance(keystoreType);
		keystore.load(new FileInputStream(new File(pkFileName)), keystorePass.toCharArray());
		
		return keystore;
		
	}

	public static byte [] getFileBytes(File file) throws Exception {
		byte [] fileBytes = new byte[(int)file.length()];
		FileInputStream fis = new FileInputStream(file);

		try
		{
			fis.read(fileBytes);
		}
		catch(Exception e)
		{
			return null;
		}
		finally
		{
			fis.close();
		}
		
		return fileBytes;
	}
}
