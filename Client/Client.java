import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;

//Exceptions
import java.net.SocketException;
import java.net.UnknownHostException;
import java.io.IOException;

public class Client {
    private DatagramSocket socket;
    private InetAddress address;
 
    private byte[] buf;
 
    public Client() {
        try {
        	socket = new DatagramSocket();
		} catch (SocketException e) {
			System.err.println("ERROR: Unable to create Datagram Socket.");
			System.exit(1);
		}
        try {
        	address = InetAddress.getByName("localhost");
		} catch (UnknownHostException e) {
			System.err.println("ERROR: Unknown Host.");
			System.exit(1);
		}
    }
 
    public String sendEcho(String msg) {
        buf = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, 4445);
        try {
        	socket.send(packet);
		} catch (IOException e) {
			System.err.println("ERROR: Unable to send packet.");
			System.exit(1);
		}
        packet = new DatagramPacket(buf, buf.length);
        try {
        	socket.receive(packet);
		} catch (IOException e) {
			System.err.println("ERROR: Unable to receive packet.");
			System.exit(1);
		}
        String received = new String(packet.getData(), 0, packet.getLength());
        return received;
    }
 
    public void close() {
        socket.close();
    }
}