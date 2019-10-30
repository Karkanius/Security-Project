class ServerHandler implements Runnable {

	private Socket clientSocket;

	public ServerHandler(Socket s) {
		this.clientSocket = s;
	}

}