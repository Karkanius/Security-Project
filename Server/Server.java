import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetAddress;

class Server {

	static public void waitForClients(ServerSocket s) {

		try {
			while (true) {
				System.out.println("Waiting for new client request");
				Socket c = s.accept();
				ServerHandler handler = new ServerHandler(c);
				new Thread(handler).start();
			}
		} catch (Exception e) {
			System.err.print("Exception: "+e);
		}

	}

	public static void main(String[] args) {
		
		if (args.length < 1) {
			System.err.print("Usage: port\n");
			System.exit(1);
		}

		int port = Integer.parseInt(args[0]);

		try {
			ServerSocket s = new ServerSocket( port, 5, InetAddress.getByName("localhost"));
			System.out.println("Started server on port "+port);
			waitForClients(s);
		} catch (Exception e) {
			System.err.print("Exception: "+e);
			System.exit(1);
		}

	}

}