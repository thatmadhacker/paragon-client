package org.thatmadhacker.paragon.client;

import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.SecretKey;

import com.thatmadhacker.utils.crypto.HashingUtils;
import com.thatmadhacker.utils.crypto.algo.ASymetric;
import com.thatmadhacker.utils.crypto.algo.Symetric;
import com.thatmadhacker.utils.misc.BASE64;

public class Client {

	public static final String HOST = "localhost";
	public static final int PORT = 6872;

	public static void main(String[] args) throws Exception {

		new Client();

	}

	@SuppressWarnings("resource")
	public Client() throws Exception {

		Socket s = new Socket(HOST, PORT);

		Scanner in = new Scanner(s.getInputStream());
		PrintWriter out = new PrintWriter(s.getOutputStream(), true);

		PublicKey serverPub = ASymetric.getPublicKeyFromByteArray(BASE64.decode(in.nextLine().replaceAll("&l", "\n")),
				"RSA");

		SecretKey key = Symetric.genKey("AES", 256);

		out.println(ASymetric.encrypt(BASE64.encode(key.getEncoded()), serverPub, serverPub.getAlgorithm())
				.replaceAll("\n", "&l"));

		in.nextLine();

		Scanner sin = new Scanner(System.in);

		System.out.print("Register or login? R/L: ");
		
		boolean login = false;
		
		if(sin.nextLine().equalsIgnoreCase("L")) {
			login = true;
		}

		if (login) {

			out.println(true);

		} else {

			out.println(false);

		}

		System.out.print("Username: ");
		String username = sin.nextLine();
		System.out.print("Password: ");
		String password = sin.nextLine();
		String passwordHash = HashingUtils.hash(password+"?salt123", HashingUtils.SHA256);

		out.println(Symetric.encrypt(username, key, key.getAlgorithm()).replaceAll("\n", "&l"));

		out.println(Symetric.encrypt(passwordHash, key, key.getAlgorithm()).replaceAll("\n", "&l"));
		
		boolean response = Boolean.valueOf(nextLine(in, key));
		
		if(!response) {
			
			if(login) {
				
				System.err.println("Wrong password!");
				
			}else {
				
				System.err.println("Username taken!");
				
			}
			
			System.exit(1);
			
		}
		
		println("{EXISTS}", out, key);
		
		println("priv.ekey", out, key);
		
		boolean exists = Boolean.valueOf(nextLine(in, key));
		
		SecretKey passwdKey = Symetric.genKey(password, "salt123", 256, "AES");
		
		KeyPair pair;
		
		if(!exists) {
			
			System.out.println("Generating key!");
			
			pair = ASymetric.genKeys("RSA", 4096);
			
			System.out.println("Finished generating key!");
			
			println("{WRITE}", out, key);
			println("priv.ekey", out, key);
			println(Symetric.encrypt(BASE64.encode(pair.getPrivate().getEncoded()), passwdKey, "AES"), out, key);
			
			println("{WRITE}", out, key);
			println("pub.key", out, key);
			println(BASE64.encode(pair.getPublic().getEncoded()).replaceAll("\n", "&l"), out, key);
			
		}else {
			
			println("{REQFILE}", out, key);
			println("priv.ekey", out, key);
			
			String privfile = nextLine(in, key).replaceAll("&l", "\n");
			
			byte[] privBytes = BASE64.decode(Symetric.decrypt(privfile, passwdKey, "AES"));
			
			PrivateKey priv = ASymetric.getPrivateKeyFromByteArray(privBytes, "RSA");
			
			println("{REQFILE}", out, key);
			println("pub.key", out, key);
			
			String file = nextLine(in, key).replaceAll("&l", "\n");
			
			PublicKey pub = ASymetric.getPublicKeyFromByteArray(BASE64.decode(file), "RSA");
			
			pair = new KeyPair(pub,priv);
			
		}
		
		while(true) {
			
			System.out.print("> ");
			
			String cmd = sin.nextLine();
			
			if(cmd.equals("get")) {
				
				System.out.print("Filename: ");
				String filename = sin.nextLine();
				
				println("{REQFILE}", out, key);
				println(filename, out, key);
				
				
				
				System.out.println(nextLine(in, key).replaceAll("&l", "\n"));
				
			}else if(cmd.equals("set")) {
				
				System.out.print("Filename: ");
				String filename = sin.nextLine();
				
				System.out.print("Data: ");
				String data = sin.nextLine();
				
				println("{WRITE}", out, key);
				println(filename, out, key);
				println(data, out, key);
				
			}else if(cmd.equalsIgnoreCase("exit")) {
				
				System.exit(0);
				
			}else if(cmd.equalsIgnoreCase("listDirs")) {
				
				System.out.print("Directory: ");
				String filename = sin.nextLine();
				
				println("{LISTDIRS}",out,key);
				println(filename,out,key);
				
				int length = Integer.valueOf(nextLine(in, key));
				
				for(int i = 0; i < length; i++) {
					
					System.out.println(nextLine(in, key));
					
				}
				
			}else if(cmd.equalsIgnoreCase("listFiles")) {
				
				System.out.print("Directory: ");
				String filename = sin.nextLine();
				
				println("{LISTFILES}",out,key);
				println(filename,out,key);
				
				int length = Integer.valueOf(nextLine(in, key));
				
				for(int i = 0; i < length; i++) {
					
					System.out.println(nextLine(in, key));
					
				}
				
			}else if(cmd.equalsIgnoreCase("send")) {
				
				System.out.print("To: ");
				String to = sin.nextLine();
				
				System.out.print("Message: ");
				String message = sin.nextLine().replaceAll("&l", "&b");
				
				
				SimpleDateFormat format = new SimpleDateFormat("yyyy.MM.dd/hh.mm.ss");
				
				String date = format.format(new Date(System.currentTimeMillis()));
				
				message = date+":\n"+message;
				
				println("{EXISTS}", out, key);
				println("outgoing/"+to+"/key.ekey", out, key);
				
				boolean keyExists = Boolean.valueOf(nextLine(in, key));
				
				SecretKey messageKey;
				
				if(!keyExists) {
					
					messageKey = Symetric.genKey("AES", 256);
					
					println("{WRITE}", out, key);
					println("outgoing/"+to+"/key.ekey", out, key);
					println(ASymetric.encrypt(BASE64.encode(messageKey.getEncoded()),pair.getPublic(),"RSA"),out, key);
					
				}else {
					
					println("{REQFILE}", out, key);
					println("outgoing/"+to+"/key.ekey", out, key);
					
					String messageKeyString = nextLine(in, key);
					
					messageKey = Symetric.genKeyFromByteArray(BASE64.decode(ASymetric.decrypt(messageKeyString.replaceAll("&l", "\n"), pair.getPrivate(),"RSA")), "AES");
					
				}
				
				println("{KEYEXISTS}", out, key);
				println(to, out, key);
				
				boolean exists2 = Boolean.valueOf(nextLine(in, key));
				
				if(!exists2) {
					
					PublicKey toKey;
					
					println("{REQPUB}", out, key);
					println(to, out, key);
					
					String pubKey = nextLine(in, key);
					
					toKey = ASymetric.getPublicKeyFromByteArray(BASE64.decode(pubKey.replaceAll("&l", "\n")), "RSA");
					
					println("{SENDKEY}", out, key);
					println(to, out, key);
					String encKey = ASymetric.encrypt(BASE64.encode(messageKey.getEncoded()),toKey,"RSA");
					println(encKey,out, key);
					
				}
				
				String encMessage = Symetric.encrypt(message, messageKey, "AES");
				
				println("{SENDMESSAGE}", out, key);
				println(to, out, key);
				println(encMessage+"\n", out, key);
				
				println("{WRITE}", out, key);
				println("outgoing/"+to+"/messages", out, key);
				println(encMessage+"\n", out, key);
				
				System.out.println("Successfully sent message!");
				
			}else if(cmd.equalsIgnoreCase("messages")) {
				
				System.out.print("From: ");
				String from = sin.nextLine();
				
				println("{EXISTS}", out, key);
				println("incoming/"+from+"/", out, key);
				
				boolean b = Boolean.valueOf(nextLine(in, key));
				
				if(!b) {
					System.out.println("No messages from that user!");
					continue;
				}
				
				println("{REQFILE}", out, key);
				println("incoming/"+from+"/key.ekey", out, key);
				
				
				
				String file = nextLine(in, key).replaceAll("&l", "\n");
				
				file = ASymetric.decrypt(file,pair.getPrivate(),"RSA");
				
				SecretKey messagesKey = Symetric.genKeyFromByteArray(BASE64.decode(file), "AES");
				
				println("{REQFILE}", out, key);
				println("incoming/"+from+"/messages", out, key);
				
				String file1 = nextLine(in, key);
				
				String[] data = file1.split("&l");
				
				for(String s1 : data) {
					
					if(!s1.equals("")) {
						
						String message = Symetric.decrypt(s1, messagesKey, "AES");
						
						System.out.println(message.replaceAll("&b", "\n"));
						System.out.println();
						
					}
					
				}
				
			}
			
		}

	}
	
	private static void println(String message, PrintWriter out, SecretKey key) throws Exception{
		out.println(Symetric.encrypt(message, key, key.getAlgorithm()).replaceAll("\n", "&l"));
	}
	
	private static String nextLine(Scanner in, SecretKey key) throws Exception{
		
		return Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, key.getAlgorithm());
		
	}

}
