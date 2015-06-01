import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

public class proxyServer {

	static ServerSocket server;
	static Socket client;
	static int port;
	static String root;
	static String defaultPage;
	static int maxThreads;
	static int threadCount = 0;
	static String logFile;
	static ArrayList<String> policyList;
	static String policyPath;
	static HashMap<String, Socket> socketMap;

	public static void main(String[] args) {
		if (args.length != 1) {
			System.err.println("Usage: java proxyServer [policy_file]");
			return;
		}
		policyList = new ArrayList<>();
		if (!parsePolicy(policyPath = args[0])) {
			System.err.println("Error parsing rules file");
			return;
		}
		File config = new File("config.ini");
		// Read ini config
		if (!parseFile(config)) {
			System.err.println("Couldn't parse ini, server will terminate");
			return;
		}
		// Create log file if doesn't exists
		File log = new File(logFile);
		if (!log.exists()) {
			try {
				log.createNewFile();
			} catch (IOException e) {
				System.err.println("Error: log file");
				return;
			}
		}

		socketMap = new HashMap<>(10);
		try {
			// Listen on port
			server = new ServerSocket(port);
			System.out.println("Listening on port: " + port);
			System.out.println();
		} catch (IOException e) {
			System.err.println("The port is used");
		}

		while (true) {
			// Check if number of threads less then 10
			while (threadCount < maxThreads) {
				try {
					// Wait for connection
					client = server.accept();
				} catch (IOException e) {
					System.err.println("Error accepitng client");
				}
				try {
					// Add socket to hash map
					socketMap.put(client.getRemoteSocketAddress().toString(),
							client);
					// Create new instant of Client Handler
					ClientHandler clienthandler = new ClientHandler(client);
					Thread thread = new Thread(clienthandler);
					thread.start();
					// Increase thread counter
					threadCount++;
				} catch (Exception e) {
					System.err.println("Internal Error");
					sendInternalError();
				}
			}
			// try {
			// // Give client a chance to get handled
			// Thread.sleep(3000);
			// } catch (InterruptedException e) {
			// System.err.println("Error interupted");
			// sendInternalError();
			// }
			// Iterate each socket and check if connection is closed
			Iterator<Entry<String, Socket>> it = socketMap.entrySet()
					.iterator();
			while (it.hasNext()) {
				Entry<?, ?> item = it.next();
				if (socketMap.get(item.getKey()).isClosed()) {
					it.remove();
					threadCount--;
				}
			}
		}

	}

	/**
	 * This method reads and parse config.ini file
	 * 
	 * @param ini
	 * @return true if succeed parsing
	 */
	private static boolean parseFile(File ini) {
		try {
			BufferedReader reader = new BufferedReader(new FileReader(ini));
			String line = reader.readLine();
			port = Integer.parseInt(line.substring(line.indexOf('=') + 1));
			line = reader.readLine();
			root = line.substring(line.indexOf('=') + 1);
			line = reader.readLine();
			defaultPage = line.substring(line.indexOf('=') + 1);
			line = reader.readLine();
			maxThreads = Integer
					.parseInt(line.substring(line.indexOf('=') + 1));
			line = reader.readLine();
			logFile = line.substring(line.indexOf('=') + 1).replace("\"", "");
			reader.close();
		} catch (FileNotFoundException e) {
			System.err.println("Error reading file");
			return false;
		} catch (IOException e) {
			System.err.println("Error reading line");
			return false;
		}
		return true;
	}

	private static void sendInternalError() {
		try {
			client.getOutputStream().write(
					"HTTP/1.0 500 Internal Error\r\n\r\n".getBytes());
			client.getOutputStream().flush();
		} catch (IOException e) {
			System.err.println("Error writing");
		}
	}

	private static boolean parsePolicy(String pathname) {
		File policy = new File(pathname);
		String line;
		try {
			BufferedReader reader = new BufferedReader(new FileReader(policy));
			while ((line = reader.readLine()) != null) {
				policyList.add(line);
			}
			reader.close();
			return true;
		} catch (FileNotFoundException e) {
			System.err.println("Error: Policy file");
			return false;
		} catch (IOException e) {
			System.err.println("Error: Policy file");
			return false;
		}
	}

}
