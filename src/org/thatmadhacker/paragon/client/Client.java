package org.thatmadhacker.paragon.client;

import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
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

		if (sin.nextLine().equalsIgnoreCase("L")) {

			out.println(true);

		} else {

			out.println(false);

		}

		System.out.print("Username: ");
		String username = sin.nextLine();
		System.out.print("Password: ");
		String passwordHash = HashingUtils.hash(sin.nextLine(), HashingUtils.SHA256);

		out.println(Symetric.encrypt(username, key, key.getAlgorithm()).replaceAll("\n", "&l"));

		out.println(Symetric.encrypt(passwordHash, key, key.getAlgorithm()).replaceAll("\n", "&l"));
		
		while(true) {
			
			System.out.print("> ");
			
			String cmd = sin.nextLine();
			
			if(cmd.equals("get")) {
				
				System.out.print("Filename: ");
				String filename = sin.nextLine();
				
				println("{REQFILE}", out, key);
				println(filename, out, key);
				
				System.out.println(nextLine(sin, key).replaceAll("&l", "\n"));
				
			}else if(cmd.equals("set")) {
				
				System.out.print("Filename: ");
				String filename = sin.nextLine();
				
				System.out.print("Data: ");
				String data = sin.nextLine();
				
				println("{WRITE}", out, key);
				println(filename, out, key);
				println(data, out, key);
				
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
