import java.net.*;
import java.io.*;

public class Client {

	public static void main(String[] args) {

		String hostname = "localhost";
		int port = 50;

		if (args.length > 0)
			hostname = args[0];
		if (args.length > 1)
			port = Integer.parseInt(args[1]);

		try (Socket socket = new Socket(hostname, port)) {

			sendThroughSocket(socket, "MyAnacondaDontWantNoneUnlessYouGotBunsHun");

			System.out.println(inputStreamToString(socket.getInputStream()));

		} catch (UnknownHostException ex) {

			System.out.println("Server not found: " + ex.getMessage());

		} catch (IOException ex) {

			System.out.println("I/O error: " + ex.getMessage());
		}

	}

	private static void sendThroughSocket(Socket socket, String str) {
		try {
			PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
			writer.println(str);
		} catch (IOException ex) {
			System.out.println("IO exception: " + ex.getMessage());
			ex.printStackTrace();
		}
	}

	private static String inputStreamToString (InputStream in) {
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(in));
			return reader.readLine();
		} catch (IOException ex) {
			System.out.println("IO exception: " + ex.getMessage());
			ex.printStackTrace();
			return null;
		}
	}
}