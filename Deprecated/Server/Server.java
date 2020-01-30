import java.io.*;
import java.net.*;
import java.util.Date;

public class Server {

	public static void main(String[] args) {

		int port = 50;
		if (args.length == 1) 
			port = Integer.parseInt(args[0]);

		try (ServerSocket serverSocket = new ServerSocket(port)) {

			System.out.println("Server is listening on port " + port);

			while (true) {
				Socket socket = serverSocket.accept();

				System.out.println("New client connected - " + inputStreamToString(socket.getInputStream()));

				OutputStream output = socket.getOutputStream();
				PrintWriter writer = new PrintWriter(output, true);

				writer.println(new Date().toString());
			}

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