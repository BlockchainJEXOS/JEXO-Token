package com.hyperbidder.util;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Properties;

import org.apache.commons.codec.binary.Hex;

public class JexoTokenHelper
{
	private static double JEXO_CURRENCY_PRICE = 1.0d;
	private static Properties props = new Properties();
	static String ETHEREUM_NETWORK = null, MY_WALLET = null, ETHEREUM_WALLET_ADDRESS_DEV = null, ETHEREUM_WALLET_ADDRESS_PROD = null, API_CHECK_BALANCE = null, API_SCAN_TRANSACTIONS = null, ETHERSCAN_IO_API_KEY = null;
	static
	{
		java.io.InputStream inStream = null;
		try
		{
			inStream = ClassLoader.getSystemResourceAsStream("jexos.properties");
			props.load(inStream);
			ETHEREUM_WALLET_ADDRESS_DEV = props.get("ETHEREUM_WALLET_ADDRESS_DEV") != null ? props.get("ETHEREUM_WALLET_ADDRESS_DEV").toString() : null;
			ETHEREUM_WALLET_ADDRESS_PROD = props.get("ETHEREUM_WALLET_ADDRESS_PROD") != null ? props.get("ETHEREUM_WALLET_ADDRESS_PROD").toString() : null;
			ETHERSCAN_IO_API_KEY = props.get("ETHERSCAN_IO_API_KEY") != null ? props.get("ETHERSCAN_IO_API_KEY").toString() : null;
			ETHEREUM_NETWORK = props.get("IS_DEV") != null && props.get("IS_DEV").toString().equalsIgnoreCase("Y") ? "ropsten" : "api";
			MY_WALLET = props.get("IS_DEV") != null && props.get("IS_DEV").toString().equalsIgnoreCase("Y") ? ETHEREUM_WALLET_ADDRESS_DEV : ETHEREUM_WALLET_ADDRESS_PROD;
			API_CHECK_BALANCE = "https://" + ETHEREUM_NETWORK + ".etherscan.io/api?module=account&action=balance&address=" + MY_WALLET + "&tag=latest&apikey=" + ETHERSCAN_IO_API_KEY;
			API_SCAN_TRANSACTIONS = "https://" + ETHEREUM_NETWORK + ".etherscan.io/api?module=account&action=txlist&address=" + MY_WALLET + "&tag=latest&startblock=#START_BLOCK#&endblock=99999999&sort=asc&apikey=" + ETHERSCAN_IO_API_KEY;
		}
		catch(IOException ioEx)
		{
			System.err.println("ERROR: " + ioEx);
			ioEx.printStackTrace();
		}
		finally
		{
			if(inStream != null)
			{
				try
				{
					inStream.close();
				} catch(Exception e) {}
			}
		}
	}
	public static void initCurrencyRates()
	{
		Connection conn = null;
		PreparedStatement pStmt = null;
		ResultSet rSet = null;
		try
		{
			conn = HyperBidderDatabaseConnector.getConnection();
			pStmt = conn.prepareStatement("select USD, DATE_UPDATED from JEXOS_CURRENCY_PRICE order by 2 desc");
			rSet = pStmt.executeQuery();
			if(rSet.next())
			{
				JEXO_CURRENCY_PRICE = rSet.getDouble(1);
			}
			System.out.println("JexoTokenHelper::initCurrencyRates(): Initialized as " + JEXO_CURRENCY_PRICE);
		}
		catch(Exception ex)
		{
			System.err.println("JexoTokenHelper::initCurrencyRates(): ERROR: " + ex);
			ex.printStackTrace();
		}
		finally
		{
			try
			{
				if(rSet != null)		rSet.close();
				if(pStmt != null)		pStmt.close();
				if(conn != null)		conn.close();
			} catch(SQLException s) {}
		}
	}
	public static String getHexStringForUser(String ID, String userLoginID)
	{
		if(userLoginID == null || userLoginID.isEmpty())
			return null;
		try
		{
			return String.valueOf(Hex.encodeHex((ID + "#" + "SECRET").getBytes("UTF8"), false));
		}
		catch(Exception e)
		{
			System.err.println("JexoTokenHelper::getHexStringForUser(" + userLoginID + "): ERROR: " + e);
			return null;
		}
	}
	public static String getUserFromHexString(String hexString)
	{
		if(hexString == null || hexString.isEmpty())
			return null;
		try
		{
			if(hexString.startsWith("0x"))
				hexString = hexString.substring(2);
			else if(hexString.startsWith("x"))
				hexString = hexString.substring(1);
			byte[] b = Hex.decodeHex(hexString.toCharArray());
			return new String(b, "UTF8");
		}
		catch(Exception e)
		{
			System.err.println("JexoTokenHelper::getUserFromHexString(" + hexString + "): ERROR: " + e);
			return null;
		}
	}
	static final String API_USD_VALUE = "https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=USD";

	static String[] getID_LoginIDFromInput(String inputData, Connection conn, PreparedStatement ps) throws Exception
	{
		if(inputData == null || inputData.trim().isEmpty())
			return null;
		String[] ret = new String[2];
		String decodedID = getUserFromHexString(inputData), logID = null;

		if(decodedID != null && !decodedID.trim().isEmpty())	// determine LoginID from the database.
		{
			if(decodedID.indexOf("#") > 0)
				decodedID = decodedID.substring(0, decodedID.indexOf("#"));
			ResultSet rs = null;
			try
			{
				ps.setString(1, decodedID);
				rs = ps.executeQuery();
				if(rs.next())
					logID = rs.getString(1);
			}
			catch(Exception e)
			{
				System.err.println("JexoTokenHelper::getID_LoginIDFromInput(): ERROR: " + e);
				e.printStackTrace();
				return null;
			}
			finally
			{
				if(rs != null)
					rs.close();
			}
		}
		ret[0] = decodedID;
		ret[1] = logID;
		return ret;
	}
	static boolean addTransaction(Connection conn, PreparedStatement ps, String[] id_LoginID, long startBlock, long timestamp, String hash, String blockHash, String from, String value, String gas, String gasPrice, String input) throws SQLException
	{
		String id = null, loginID = null;
		if(id_LoginID != null && id_LoginID[0] != null && !id_LoginID[0].trim().isEmpty())
		{
			System.out.println("addTransaction(): " + id_LoginID[0] + ", " + id_LoginID[1] + ", " + timestamp + ", " + from + ", " + value);
			id = id_LoginID[0];
			loginID = id_LoginID[1];
		}
		//TX_HASH, TX_DATA, LOGIN_ID, ID, JEXOS_CREDITED, JEXOS_USD_VALUE_ON_DATE, UNITS_PURCHASED, GAS_LIMIT, GAS_PRICE, TX_COST, TRANSACTION_DATE, JEXOS_IMPORTED_DATE, START_BLOCK
		ps.setString(1, hash);
		ps.setString(2, input);
		ps.setString(3, loginID != null && loginID.length() < 128 ? loginID : null);
		ps.setString(4, isInteger(id) ? id : "0");
		double val = Double.parseDouble(value + "E-18"), usdVal = getEthereumUSDValue(val);
		ps.setDouble(5, val);
		ps.setDouble(6, usdVal);
		ps.setDouble(7, (val * usdVal)/JEXO_CURRENCY_PRICE);
		ps.setDouble(8, Double.parseDouble(gas));
		ps.setDouble(9, Double.parseDouble(gasPrice));
		ps.setDouble(10, 0.0d);
		ps.setTimestamp(11, new java.sql.Timestamp(timestamp));
		ps.setTimestamp(12, new java.sql.Timestamp(System.currentTimeMillis()));
		ps.setLong(13, startBlock);
		ps.setString(14, hash);
		int x = ps.executeUpdate();
		if(x > 0)
			sendMailOnUserTransfer(loginID, id, hash, val, usdVal, timestamp);
		return x > 0;
	}
	private static void sendMailOnUserTransfer(String loginID, String id, String hash, double val, double usdVal, long timestamp)
	{
		if(props.get("FROM_EMAIL") != null && props.get("ADMIN_EMAIL") != null)
		{
			String mailMessage="Dear Admin,<br><br>";
			mailMessage = mailMessage +  "<br><br>User " + loginID + " (ID: " + id + ") transferred: " + getFormattedNumberString(val) + " ETH at " + new java.sql.Timestamp(timestamp) + ", valued at " + getFormattedNumberString(usdVal) + "USD per ETH";
			String adminEmail = props.get("FROM_EMAIL").toString();
			String mailSubject="Jexo user wallet balance update";
	        MailBase mailBase = new MailBase(adminEmail, props.get("ADMIN_EMAIL").toString(), mailSubject, mailMessage);
	        mailBase.send();
		}
		else
			System.err.println("jexos.properties not defined with FROM_EMAIL and ADMIN_EMAIL properties.");
	}
	@SuppressWarnings("unchecked")
	public static void scanOurWallet()
	{
		System.out.println("Starting timed task @ " + new java.sql.Timestamp(System.currentTimeMillis()));
		java.io.BufferedReader buffReader = null;
		try
		{
			/* trust etherscan.io */
			javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{new javax.net.ssl.X509TrustManager() {
				public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {}
				public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {}
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					// or you can return null too
					return new java.security.cert.X509Certificate[0];
				}
		    }};
			javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
		    sc.init(null, trustAllCerts, new java.security.SecureRandom());
		    javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {
		        public boolean verify(String string, javax.net.ssl.SSLSession sslSession) {
		        	if(string != null && string.indexOf("etherscan.io") >= 0)
		        	{
		        		System.out.println("JexoTokenHelper::doJob(): Trusting etherscan.io ...");
		            	return true;
		        	}
		        	return false;
		        }
		    });
			/* */
		    final String API_CHECK_BALANCE = "https://" + ETHEREUM_NETWORK + ".etherscan.io/api?module=account&action=balance&address=" + MY_WALLET + "&tag=latest&apikey=" + ETHERSCAN_IO_API_KEY;
			java.net.URL apiEndPoint = new java.net.URL(API_CHECK_BALANCE);
	        java.net.URLConnection urlConn = apiEndPoint.openConnection();
	        System.out.println("JexoTokenHelper::startWalletScanProcess(): opened connection to: " + API_CHECK_BALANCE);
	        buffReader = new java.io.BufferedReader(new java.io.InputStreamReader(urlConn.getInputStream()));
        	com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
			java.util.Map<String, String> jsonMap = null;
        	try
        	{
        		jsonMap = mapper.readValue(buffReader, java.util.Map.class);
        	} catch(NullPointerException nEx) { return; }
			if(jsonMap != null && jsonMap.containsKey("result"))
			{
				double walletBalance = Double.parseDouble(jsonMap.get("result") + "E-18");
				System.out.println("Our wallet balance is: " + walletBalance + "***\n");
				Connection conn = null;
				PreparedStatement ps = null;
				ResultSet rs = null;
				double balance = 0.0d;
				long startBlock = 0;
				boolean added = false;
				try
				{
					conn = HyperBidderDatabaseConnector.getConnection();
					ps = conn.prepareStatement("select BALANCE, START_BLOCK from JEXOS_CURRENT_BALANCE");
					rs = ps.executeQuery();
					if(rs.next())
					{
						balance = rs.getDouble(1);
						startBlock = rs.getLong(2);
					}
					else
					{
						rs.close();	rs = null;
						ps.close();
						ps = conn.prepareStatement("insert into JEXOS_CURRENT_BALANCE(BALANCE) values(?)");
						ps.setDouble(1, walletBalance);
						ps.executeUpdate();
						added = true;
					}
					if(!added && balance != walletBalance)
					{
						rs.close();	rs = null;
						ps.close();
						ps = conn.prepareStatement("update JEXOS_CURRENT_BALANCE set BALANCE = ?");
						ps.setDouble(1, walletBalance);
						ps.executeUpdate();
						added = true;
					}
				}
				catch(Exception e)
				{
					System.err.println("JexoTokenHelper::doJob() ERROR: " + e);
					e.printStackTrace();
				}
				finally
				{
					if(rs != null)
						rs.close();
					if(ps != null)
						ps.close();
					HyperBidderDatabaseConnector.close(conn);
					if(buffReader != null)
					{
						buffReader.close();
						buffReader = null;
					}
				}
				if(added)	// scan transactions and send an email too
				{
					apiEndPoint = new java.net.URL(JexoTokenHelper.API_SCAN_TRANSACTIONS.replaceFirst("#START_BLOCK#", String.valueOf(startBlock)));
			        urlConn = apiEndPoint.openConnection();
			        buffReader = new java.io.BufferedReader(new java.io.InputStreamReader(urlConn.getInputStream()));
		        	mapper = new com.fasterxml.jackson.databind.ObjectMapper();
					java.util.Map<String, java.util.ArrayList<java.util.HashMap<String, String>>> jsonMap2 = mapper.readValue(buffReader, java.util.Map.class);
					if(jsonMap2 != null && jsonMap2.containsKey("result"))
					{
						Connection conn2 = null;
						PreparedStatement ps2 = null, ps1 = null;
						try
						{
							conn2 = HyperBidderDatabaseConnector.getConnection();
							ps1 = conn2.prepareStatement("select LOGIN_ID from JEXOS_USERS where ID = ?");
							ps2 = conn2.prepareStatement("insert into JEXOS_TRANSACTIONS(TX_HASH, TX_DATA, LOGIN_ID, ID, JEXOS_CREDITED, JEXOS_USD_VALUE_ON_DATE, UNITS_PURCHASED, GAS_LIMIT, GAS_PRICE, TX_COST, TRANSACTION_DATE, JEXOS_IMPORTED_DATE, START_BLOCK) select ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? from dual where not exists (select 1 from JEXOS_TRANSACTIONS where TX_HASH = ?)");
							java.util.ArrayList<java.util.HashMap<String, String>> resultList = jsonMap2.get("result");
							for(java.util.HashMap<String, String> map : resultList)
							{
								String isError = map.get("isError");
								if(isError != null && !"0".equals(isError))
									continue;
								startBlock = Long.parseLong(map.get("blockNumber"));
								long timestamp = Long.parseLong(map.get("timeStamp"))*1000;
								String hash = map.get("hash");
								String blockHash = map.get("blockHash");
								String from = map.get("from");
								String value = map.get("value");
								String gas = map.get("gas"), gasPrice = map.get("gasPrice");
								String input = map.get("input");
								String[] id_loginID = getID_LoginIDFromInput(input, conn2, ps1);
								addTransaction(conn2, ps2, id_loginID, startBlock, timestamp, hash, blockHash, from, value, gas, gasPrice, input);
							}
							updateLatestBlock(startBlock, conn2);
						}
						catch(Exception e)
						{
							System.err.println("ERROR: " + e);
							e.printStackTrace();
						}
						finally
						{
							if(ps1 != null)
								ps1.close();
							if(ps2 != null)
								ps2.close();
							if(conn2 != null)
								conn2.close();
						}
					}
					if(props.get("EMAIL_FROM") != null && props.get("ADMIN_EMAIL") != null)
					{
						String mailMessage="Dear Admin,<br><br>";
						mailMessage = mailMessage +  "<br><br>Our wallet balance updated from: " + balance + " to " + walletBalance;
						String adminEmail = props.get("EMAIL_FROM").toString();
						String mailSubject="Our wallet balance update";
				        MailBase mailBase = new MailBase(adminEmail, props.get("ADMIN_EMAIL").toString(), mailSubject, mailMessage);
				        mailBase.send();
					}
					else
						System.err.println("jexos.properties not defined with FROM_EMAIL and ADMIN_EMAIL properties.");
				}
			}
		}
		catch(Exception e)
		{
			System.err.println("JexoTokenHelper::startWalletScanProcess(): JSON parsing error: " + e);
			e.printStackTrace();
	    	return;
		}
		finally
		{
			try { if(buffReader != null) buffReader.close(); } catch(Exception e) {}
		}
		System.out.println("Finished scanning.");
	}
	private static void updateLatestBlock(long startBlock, Connection conn) throws SQLException
	{
		PreparedStatement ps = null;
		try
		{
			ps = conn.prepareStatement("update JEXOS_CURRENT_BALANCE set START_BLOCK = ? where ? >= IFNULL(START_BLOCK, 0)");
			ps.setLong(1, startBlock);
			ps.setLong(2, startBlock);
			ps.executeUpdate();
		}
		finally
		{
			if(ps != null)
				ps.close();
		}
	}
	public static double getEthereumUSDValue(double etherUnits)
	{
		java.io.BufferedReader buffReader = null;
		double retVal = 0.0d;
		try
		{
			/* trust cryptocompare.com */
			javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{new javax.net.ssl.X509TrustManager() {
				public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {}
				public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {}
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					// or you can return null too
					return new java.security.cert.X509Certificate[0];
				}
		    }};
			javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
		    sc.init(null, trustAllCerts, new java.security.SecureRandom());
		    javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {
		        public boolean verify(String string, javax.net.ssl.SSLSession sslSession) {
		        	if(string != null && string.indexOf("cryptocompare.com") >= 0)
		        	{
		        		System.out.println("JexoTokenHelper::doJob(): Trusting cryptocompare.com ...");
		            	return true;
		        	}
		        	return false;
		        }
		    });
			/* */
			java.net.URL apiEndPoint = new java.net.URL(JexoTokenHelper.API_USD_VALUE);
	        java.net.URLConnection urlConn = apiEndPoint.openConnection();
	        buffReader = new java.io.BufferedReader(new java.io.InputStreamReader(urlConn.getInputStream()));
	        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        	@SuppressWarnings("unchecked")
			//String jsonMap = mapper.readValue(buffReader, String.class);
	        java.util.Map<String, Double> jsonMap = mapper.readValue(buffReader, java.util.Map.class);
        	System.out.println("JexoTokenHelper::getEthereumUSDValue(" + etherUnits + "):" + jsonMap);
			if(jsonMap != null && jsonMap.containsKey("USD"))
			{
				retVal = jsonMap.get("USD");
			}
		}
		catch(Exception e)
		{
			Connection conn = null;
			PreparedStatement ps = null;
			ResultSet rs = null;
			try
			{
				conn = HyperBidderDatabaseConnector.getConnection();
				ps = conn.prepareStatement("select JEXOS_USD_VALUE_ON_DATE from JEXOS_TRANSACTIONS order by JEXOS_IMPORTED_DATE desc limit 2");
				rs = ps.executeQuery();
				if(rs.next())
					retVal = rs.getDouble(1);
			}
			catch(Exception e2)
			{
				System.err.println("JexoTokenHelper::getEthereumUSDValue() ERROR: " + e2);
				e.printStackTrace();
			}
			finally
			{
				HyperBidderDatabaseConnector.close(rs, ps);
				HyperBidderDatabaseConnector.close(conn);
			}
			return retVal;
		}
		finally
		{
			if(buffReader != null)
			{
				try { buffReader.close(); } catch(IOException ioEx) {}
			}
		}
		return retVal;
	}
	// A few utility methods:
	public static boolean isInteger(String s)
	{
		try
		{
			Integer.parseInt(s);
			return true;
		} catch(NumberFormatException e ) { return false; }
	}
	public static String getFormattedNumberString(double a_Num)
	{
		String ret = new DecimalFormat("#.00", new DecimalFormatSymbols(java.util.Locale.ENGLISH)).format(a_Num);
		return ret != null && ret.startsWith(".") ? "0" + ret : ret;
	}
}
