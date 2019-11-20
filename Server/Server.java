import java.lang.Thread;
import java.net.DatagramSocket;
import java.net.DatagramPacket;

//Exceptions
import java.net.InetAddress;
import java.net.SocketException;
import java.io.IOException;

public class Server extends Thread {

	private DatagramSocket socket;
	private byte[] buf = new byte[256];
	private int basePort = 8000;

	public Server() {
		try {
			this.socket = new DatagramSocket(basePort);
		} catch (SocketException e) {
			System.err.println("ERROR: Unable to create Datagram Socket.");
			System.exit(1);
		}
	}

	public void run() {
		while (true) {
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			try {
				this.socket.receive(packet);
			} catch (IOException e) {
				System.err.println("ERROR: Unable to create Datagram Socket.");
				System.exit(1);
			}
			
			InetAddress address = packet.getAddress();
			int port = packet.getPort();
			packet = new DatagramPacket(buf, buf.length, address, port);
			String received = new String(packet.getData(), 0, packet.getLength());
			
			if (received.equals("end")) {
				break;
			}
			try {
				this.socket.send(packet);
			} catch (IOException e) {
				System.err.println("ERROR: Unable to create Datagram Socket.");
				System.exit(1);
			}
		}
		this.socket.close();
	}
}