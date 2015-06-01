import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

public class ClientHandler implements Runnable {

	final static String CRLF = "\r\n";
	final static String METHOD_GET = "GET";
	final static String METHOD_POST = "POST";
	final static String METHOD_OPTIONS = "OPTIONS";
	final static String METHOD_TRACE = "TRACE";
	final static String METHOD_HEAD = "HEAD";
	final static String SPACE = " ";
	final static String SEPARATOR = ", ";
	final static String COLON = ":";
	final static String EQUALS = "=";
	final static int CODE_200 = 200;
	final static int CODE_404 = 404;
	final static int CODE_501 = 501;
	final static int CODE_400 = 400;
	final static int CODE_403 = 403;
	final static int CHUNK = 0x64;
	final static String NOT_IMPLEMENTED = "Not Implemented";
	final static String FILE_NOT_FOUND = "Not Found";
	final static String BAD_REQUEST = "Bad Request";
	final static String ACCESS_DENIED = "Access Denied";
	final static String OK = "OK";

	final static String LOG_URL = "http://content-proxy/logs";
	final static String POLICY_URL = "http://content-proxy/policies";
	final static String REMOVE = "remove";
	final static String ADD = "add";
	final static String MODIFY = "modify";
	final static String SUBMIT = "submit";

	final static String BLOCK_SITE = "block-site";
	final static String BLOCK_RESOURCE = "block-resource";
	final static String BLOCK_IP_MASK = "block-ip-mask";

	// Client
	Socket sock;
	BufferedReader reader;

	// HTTPRequest
	String requestLine;
	HashMap<String, String> headers;
	HashMap<String, String> parameters;

	// File content
	byte[] fileContent;

	public ClientHandler(Socket sock) {
		this.sock = sock;
	}

	@Override
	public void run() {
		// Initiate
		headers = new HashMap<>();
		parameters = new HashMap<>();
		try {
			reader = new BufferedReader(new InputStreamReader(
					sock.getInputStream()));
		} catch (IOException e) {
			System.err.println("Error BufferedReader streams");
		}

		// Read the HTTP request that sent from the client
		if (readHTTPRequest() != 0) {
			sendBadRequest();
			closeStreams();
			return;
		}
		// Create new instant that represents the HTTP request
		HTTPRequest httprequest = new HTTPRequest(requestLine, headers,
				parameters);
		// Write a response according the request
		writeHTTPResponse(httprequest);

		closeStreams();
	}

	private void closeStreams() {
		try {
			reader.close();
			sock.close();
		} catch (IOException e) {
			System.err.println("Error closing streams");
		}
	}

	/**
	 * This method reads the request from the client and parses it
	 * 
	 * @return 0 if everything is good
	 */
	private int readHTTPRequest() {
		String line;
		try {
			requestLine = reader.readLine();
			System.out.println("Request:");
			System.out.println(requestLine);
			String method = requestLine.substring(0, requestLine.indexOf(' '));
			String version = requestLine.split(" ")[2];
			// Check valid request
			if (!version.equalsIgnoreCase("HTTP/1.0")
					&& !version.equalsIgnoreCase("HTTP/1.1")) {
				return 1;
			}
			while ((line = reader.readLine()) != null) {
				System.out.println(line);
				if (!line.equalsIgnoreCase("")) {
					String key = line.substring(0, line.indexOf(':'))
							.toLowerCase();
					String value = line.substring(line.indexOf(':') + 2)
							.toLowerCase();
					// Saves HTTP request headers in hash map
					headers.put(key, value);
				} else {
					// Check if should read parameter line for POST method
					if (method.equalsIgnoreCase(METHOD_POST)) {
						if (headers.containsKey(HTTPRequest.CONTENT_LENGTH
								.toLowerCase())) {

							char[] cbuf = new char[Integer.parseInt(headers
									.get(HTTPRequest.CONTENT_LENGTH
											.toLowerCase()))];
							reader.read(cbuf);
							parseParameters(new String(cbuf));
						}
						return 0;
					} else {
						return 0;
					}
				}
			}
		} catch (IOException e) {
			System.err.println("Error reading from client");
			return 2;
		} catch (Exception f) {
			return 1;
		}
		return 0;
	}

	/**
	 * This method reads parameters form HTTP request
	 * 
	 * @param line
	 */
	private void parseParameters(String line) {
		String[] params = line.split("&");
		for (int i = 0; i < params.length; i++) {
			String key = params[i].substring(0, params[i].indexOf('='));
			String value = params[i].substring(params[i].indexOf('=') + 1);
			if (!parameters.containsKey(key)) {
				parameters.put(key, value);
			}
		}
	}

	/**
	 * This method return a response to the client according the request he sent
	 * 
	 * @param request
	 */
	private void writeHTTPResponse(HTTPRequest request) {
		try {
			if (policyEditAction(request)) {
				savePolicy(proxyServer.policyPath);
				editPolicy(request);
				sock.getOutputStream().flush();
				return;
			}
			if (request.getFile().equalsIgnoreCase(LOG_URL)) {
				showLog(request);
				sock.getOutputStream().flush();
				return;
			}
			if (request.getFile().equalsIgnoreCase(POLICY_URL)) {
				editPolicy(request);
				sock.getOutputStream().flush();
				return;
			}
			if (checkRules(request)) {
				if (request.getHost().equalsIgnoreCase(
						"localhost" + COLON + proxyServer.port)) {
					switch (request.getMethod()) {
					case METHOD_GET:
					case METHOD_POST:
						// Send headers and check for file not found
						if (sendHeaderResponse(request) != 0) {
							sendFileNotFoundResponse(request);
							break;
						}

						// If user asks for response in chunks
						if (request.isChunked()) {
							sendContentInChunks();
						} else {
							sendContent();
						}
						break;
					case METHOD_OPTIONS:
						if (sendOptionsResponse(request) != 0) {
							sendFileNotFoundResponse(request);
						}
						break;
					case METHOD_HEAD:
						sendHeaderResponse(request);
						break;
					case METHOD_TRACE:
						sendTraceResponse(request);
						break;
					default:
						// 501
						sendNotImplemented(request);
						break;
					}
				} else {
					sendRequest(request);
				}
			}

			sock.getOutputStream().flush();

		} catch (IOException e) {
			System.err.println("Error writing response");
		}
	}

	/**
	 * This method reads a file into a byte array
	 * 
	 * @param file
	 * @return
	 */
	private byte[] readFile(File file) {
		try {
			FileInputStream fis = new FileInputStream(file);
			byte[] bFile = new byte[(int) file.length()];
			// read until the end of the stream.
			while (fis.available() != 0) {
				fis.read(bFile, 0, bFile.length);
			}
			fis.close();
			return bFile;
		} catch (FileNotFoundException e) {
			return null;
		} catch (IOException e) {
			return null;
		}
	}

	/**
	 * This method writes to socket output stream
	 * 
	 * @param stream
	 *            the string you want to send
	 */
	private void writeStream(String stream) {
		try {
			this.sock.getOutputStream().write(stream.getBytes());
			System.out.print(stream);
		} catch (IOException e) {
			System.err.println("Error writing streams to socket");
		}
	}

	/**
	 * This method checks if user asked for Params_info.html
	 * 
	 * @param request
	 * @return true if user asked for it
	 */
	/*
	 * private boolean isParamInfo(HTTPRequest request) { if
	 * (request.getFile().equalsIgnoreCase("Params_info.html")) { if
	 * (!request.getParameters().isEmpty()) { return true; } } return false; }
	 */

	/**
	 * This method sends params_info.html to output stream
	 * 
	 * @param request
	 * @return HTTP response contains param_info
	 */
	/*
	 * private void sendParamInfo(HTTPRequest request) { StringBuffer
	 * params_info = new StringBuffer();
	 * params_info.append("<html><head></head><body><table>"); for (String entry
	 * : request.getParameters().keySet()) { params_info.append("<tr><td>" +
	 * entry + "</td><td>" + request.getParameters().get(entry) + "</td><tr>");
	 * } params_info.append("</table></body></html>");
	 * System.out.println("Response:"); writeStream(request.getVersion() + SPACE
	 * + CODE_200 + SPACE + OK + CRLF); writeStream(HTTPRequest.CONTENT_TYPE +
	 * ": " + "text/html" + CRLF); writeStream(HTTPRequest.CONTENT_LENGTH + ": "
	 * + params_info.length() + CRLF); writeStream(CRLF);
	 * writeStream(params_info.toString()); writeStream(CRLF + CRLF); }
	 */

	/**
	 * This method sends File Not Found response
	 * 
	 * @param request
	 */
	private void sendFileNotFoundResponse(HTTPRequest request) {
		writeStream(request.getVersion() + SPACE + CODE_404 + SPACE
				+ FILE_NOT_FOUND + CRLF);
		writeStream(CRLF);
		try {
			sock.getOutputStream().write(
					"<html><body><h1>File Not Found</h1></body></html>"
							.getBytes());
			sock.getOutputStream().write((CRLF + CRLF).getBytes());
		} catch (IOException e) {
			System.err.println("Error: File Not Found");
		}
	}

	/**
	 * This method sends access denied response for HTTP requests that aren't
	 * meets policy requirements
	 * 
	 * @param request
	 */
	private void sendAccessDenied(HTTPRequest request, String rule) {
		writeStream(request.getVersion() + SPACE + CODE_403 + SPACE
				+ ACCESS_DENIED + CRLF);
		writeStream(CRLF);
		try {
			sock.getOutputStream().write(
					"<html><body><h1>Access Denied</h1><br>Rule: ".getBytes());
			sock.getOutputStream().write(rule.getBytes());
			sock.getOutputStream().write("</body></html>".getBytes());
			sock.getOutputStream().write((CRLF + CRLF).getBytes());
		} catch (IOException e) {
			System.err.println("Error: Access Denied");
		}
	}

	/**
	 * This method sends Not Implemented response for HTTP requests that aren't
	 * supported
	 * 
	 * @param request
	 * @return
	 */
	private void sendNotImplemented(HTTPRequest request) {
		StringBuilder sb = new StringBuilder();
		sb.append(request.getVersion() + SPACE + CODE_501 + SPACE
				+ NOT_IMPLEMENTED);
		writeStream(CRLF + CRLF);
		writeStream(sb.toString());
	}

	/**
	 * This method sends Bad Request response
	 */
	private void sendBadRequest() {
		System.out.println();
		System.out.println("Response: ");
		writeStream("HTTP/1.0" + SPACE + CODE_400 + SPACE + BAD_REQUEST + CRLF);
		writeStream(CRLF + CRLF);
		try {
			sock.getOutputStream().flush();
		} catch (IOException e) {
			System.err.println("Error sending Bad Requests");
		}
	}

	/**
	 * This method sends OPTIONS method content
	 * 
	 * @param request
	 */
	private int sendOptionsResponse(HTTPRequest request) {
		String path;
		File file;

		System.out.println("Response:");
		// File path
		path = proxyServer.root + request.getFile();
		// Take default page
		if (path.equalsIgnoreCase(proxyServer.root)) {
			file = new File(path + proxyServer.defaultPage);
		} else {
			file = new File(path);
		}
		// Check if file exists
		if (!file.exists()) {
			return 1;
		}
		// Check if file is under root directory, deny surfing
		try {
			if (!file.getCanonicalPath().toLowerCase()
					.startsWith(proxyServer.root.toLowerCase())) {
				return 1;
			}
		} catch (IOException e) {
			System.err.println("Error get canonical path in head method");
		}
		writeStream(request.getVersion() + SPACE + CODE_200 + SPACE + OK + CRLF);
		writeStream("Allow: " + METHOD_GET + SEPARATOR + METHOD_POST
				+ SEPARATOR + METHOD_OPTIONS + SEPARATOR + METHOD_TRACE
				+ SEPARATOR + METHOD_HEAD + CRLF + CRLF);
		return 0;
	}

	/**
	 * This method sends response headers
	 * 
	 * @param request
	 */
	private int sendHeaderResponse(HTTPRequest request) {
		String path;
		File file;

		System.out.println("Response:");
		// File path
		path = proxyServer.root + request.getFile().substring(1);
		// Take default page
		if (path.equalsIgnoreCase(proxyServer.root)) {
			file = new File(path + proxyServer.defaultPage);
		} else {
			file = new File(path);
		}
		// Check if file exists
		if (!file.exists()) {
			return 1;
		}
		// Check if file is under root directory, deny surfing
		try {
			if (!file.getCanonicalPath().toLowerCase()
					.startsWith(proxyServer.root.toLowerCase())) {
				return 1;
			}
		} catch (IOException e) {
			System.err.println("Error get canonical path in head method");
		}
		// Read the file
		fileContent = readFile(file);
		// Problem reading the file
		if (fileContent == null) {
			return 1;
		}

		writeStream((request.getVersion() + SPACE + CODE_200 + SPACE + OK + CRLF));
		if (request.isHtml()) {
			writeStream((HTTPRequest.CONTENT_TYPE + ": " + "text/html" + CRLF));
		} else if (request.isImage()) {
			writeStream((HTTPRequest.CONTENT_TYPE + ": " + "image" + CRLF));
		} else if (request.isIcon()) {
			writeStream((HTTPRequest.CONTENT_TYPE + ": " + "icon" + CRLF));
		} else {
			writeStream((HTTPRequest.CONTENT_TYPE + ": "
					+ "application/octet-stream" + CRLF));
		}
		if (request.isChunked()) {
			writeStream((HTTPRequest.TRANSFER_ENCODING + ": "
					+ HTTPRequest.CHUNKED + CRLF));
		} else {
			writeStream((HTTPRequest.CONTENT_LENGTH + ": " + fileContent.length + CRLF));
		}
		writeStream((CRLF));
		return 0;
	}

	/**
	 * This method send TRACE method content
	 * 
	 * @param request
	 */
	private void sendTraceResponse(HTTPRequest request) {
		sendHeaderResponse(request);
		if (request.isChunked()) {
			StringBuilder sb = new StringBuilder();
			sb.append(request.getMethod() + SPACE + request.getFile() + SPACE
					+ request.getVersion() + CRLF);
			for (String key : headers.keySet()) {
				sb.append(key + ": " + headers.get(key) + CRLF);
			}
			int counter = 0;
			while (sb.length() > counter + CHUNK) {
				writeStream(Integer.toHexString(CHUNK) + CRLF);
				for (int i = counter; i < counter + CHUNK; i++) {
					writeStream(sb.substring(i, i + 1));
				}
				writeStream(CRLF + CRLF);
				counter += CHUNK;
			}
			writeStream(Integer.toHexString(sb.length() - counter) + CRLF);
			for (int i = counter; i < sb.length(); i++) {
				writeStream(sb.substring(i, i + 1));
			}
			writeStream(CRLF);
			writeStream(Integer.toString(0));
			writeStream(CRLF + CRLF);
		} else {
			writeStream(request.getMethod() + SPACE + request.getFile() + SPACE
					+ request.getVersion() + CRLF);
			for (String key : headers.keySet()) {
				writeStream(key + ": " + headers.get(key) + CRLF);
			}
			writeStream(CRLF + CRLF);
		}
	}

	/**
	 * This method sends file content in chunks
	 */
	private void sendContentInChunks() {
		try {
			int counter = 0;
			while (fileContent.length > counter + CHUNK) {
				sock.getOutputStream().write(
						(Integer.toHexString(CHUNK) + CRLF).getBytes());
				for (int i = counter; i < counter + CHUNK; i++) {
					sock.getOutputStream().write(fileContent[i]);
				}
				sock.getOutputStream().write((CRLF + CRLF).getBytes());
				counter += CHUNK;
			}
			sock.getOutputStream().write(
					(Integer.toHexString(fileContent.length - counter) + CRLF)
							.getBytes());
			for (int i = counter; i < fileContent.length; i++) {
				sock.getOutputStream().write(fileContent[i]);
			}
			sock.getOutputStream().write((CRLF).getBytes());
			sock.getOutputStream().write("0".getBytes());
			sock.getOutputStream().write((CRLF + CRLF).getBytes());
		} catch (IOException e) {
			System.err.println("Error writing content in chunks");
		}
	}

	/**
	 * This method send file content
	 */
	private void sendContent() {
		try {
			for (int i = 0; i < fileContent.length; i++) {
				sock.getOutputStream().write(fileContent[i]);
			}
			sock.getOutputStream().write((CRLF + CRLF).getBytes());
		} catch (IOException e) {
			System.err.println("Error writing content");
		}
	}

	/**
	 * This method sends the request to desired host
	 * 
	 * @param request
	 */
	private void sendRequest(HTTPRequest request) {
		String host = request.getURL();
		int read;
		try {
			URL connection = new URL(host);
			InputStream in = connection.openStream();
			while ((read = in.read()) != -1) {
				sock.getOutputStream().write(read);
			}
			in.close();
		} catch (MalformedURLException e) {
			System.err.println("Error: send request url");
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println(request.getFile());
			System.err.println(host);
			System.err.println("Error: send request input stream");
		}
	}

	/**
	 * This method checks if the request meets the requirement of the policy
	 * file
	 * 
	 * @param request
	 * @return
	 */
	private boolean checkRules(HTTPRequest request) {
		ArrayList<String> policyMap = proxyServer.policyList;
		for (String rule : policyMap) {
			String policy = rule.substring(0, rule.indexOf(" "));
			String value = rule.substring(rule.indexOf(" ") + 1).replace("\"",
					"");
			switch (policy) {
			case BLOCK_SITE:
				// Check if requested host contains block keyword
				if (request.getFile().contains(value)) {
					writeLog(request.getRequestLine(), rule,
							System.currentTimeMillis());
					return false;
				}
				break;
			case BLOCK_RESOURCE:
				// Check if requested resource contains block keyword
				if (request.getFile().contains(value)) {
					writeLog(request.getRequestLine(), rule,
							System.currentTimeMillis());
					sendAccessDenied(request, rule);
					return false;
				}
				break;
			case BLOCK_IP_MASK:
				// Check if requested ip is not blocked
				String host = request.getFile().replaceAll("http://", "");
				host = host.substring(0, host.indexOf('/'));
				String ipmask = value;
				String ip = ipmask.substring(0, ipmask.indexOf("/"));
				String mask = ipmask.substring(ipmask.indexOf("/") + 1);
				try {
					byte[] hostArr = InetAddress.getByName(host).getAddress();
					int hostRep = ((hostArr[0] & 0xFF) << 24)
							| ((hostArr[1] & 0xFF) << 16)
							| ((hostArr[2] & 0xFF) << 8)
							| ((hostArr[3] & 0xFF) << 0);
					byte[] ipArr = InetAddress.getByName(ip).getAddress();
					int iprep = ((ipArr[0] & 0xFF) << 24)
							| ((ipArr[1] & 0xFF) << 16)
							| ((ipArr[2] & 0xFF) << 8)
							| ((ipArr[3] & 0xFF) << 0);
					int maskrep = (-1) << (32 - Integer.parseInt(mask));
					int lowest = iprep & maskrep;
					int highest = lowest + (~maskrep);
					if (hostRep <= highest && hostRep >= lowest) {
						return false;
					}
				} catch (UnknownHostException e) {
					System.err.println("Error: ip mask");
				}
				break;
			}
		}
		return true;
	}

	/**
	 * This method writes to log file
	 * 
	 * @param request
	 * @param rule
	 * @param time
	 */
	private void writeLog(String request, String rule, long time) {
		File log = new File(proxyServer.logFile);
		Date date = new Date(time);
		try {
			PrintWriter writer = new PrintWriter(new FileWriter(log, true));
			writer.println(date + COLON + CRLF + "Blocked" + COLON + SPACE
					+ request + CRLF + "Reason" + COLON + SPACE + rule + CRLF);
			writer.flush();
			writer.close();
		} catch (FileNotFoundException e) {
			System.err.println("Error: log file");
		} catch (IOException e) {
			System.err.println("Error: log file");
		}
	}

	/**
	 * This method shows the log file when user asks for
	 * http://content-proxy/logs
	 * 
	 * @param request
	 */
	private void showLog(HTTPRequest request) {
		File log = new File(proxyServer.logFile);
		String line;
		try {
			if (log.length() == 0) {
				sock.getOutputStream().write(
						"<html><body><h2>Log file is empty! </h2></body></html>"
								.getBytes());
				return;
			}
			BufferedReader reader = new BufferedReader(new FileReader(log));
			sock.getOutputStream().write(
					"<html><body><h1>Log File:</h1><br>".getBytes());
			while ((line = reader.readLine()) != null) {
				sock.getOutputStream().write(line.getBytes());
				sock.getOutputStream().write("<br>".getBytes());
			}
			sock.getOutputStream().write("</body></html>".getBytes());
			reader.close();
		} catch (FileNotFoundException e) {
			System.err.println("Error: log show");
		} catch (IOException e) {
			System.err.println("Error: log show");
		}
	}

	/**
	 * This method shows edit policy page when user asks for
	 * http://content-proxy/policies
	 * 
	 * @param request
	 */
	private void editPolicy(HTTPRequest request) {
		try {
			sock.getOutputStream().write(
					"<html><body><h1>Policy editor</h1><br>".getBytes());
			// sock.getOutputStream().write(addPolicy().getBytes());
			sock.getOutputStream().write(showPolicies().getBytes());
			sock.getOutputStream().write("</body></html>".getBytes());
		} catch (IOException e) {
			System.err.println("Error: Edit policy");
		}
	}

	/**
	 * This method return a form with text area that has each policy when you
	 * click on submit button the data send to proxy
	 * 
	 * @return
	 */
	private String showPolicies() {
		StringBuilder sb = new StringBuilder();
		sb.append("<form action=" + POLICY_URL + " method=\"post\">");
		sb.append("<textarea rows=\"20\" cols=\"50\" name=\"submit\">");
		for (String policy : proxyServer.policyList) {
			sb.append(policy + CRLF);
		}
		sb.append("</textarea><br>");
		sb.append("<input type=\"submit\" value=\"Submit\">");
		sb.append("</form>");
		return sb.toString();
	}

	/**
	 * This method checks if policy page was edited
	 * 
	 * @param request
	 * @return
	 */
	private boolean policyEditAction(HTTPRequest request) {
		// Check if button was submit
		if (!request.getParameters().containsKey(SUBMIT)) {
			return false;
		}
		String policies = request.getParameters().get(SUBMIT);
		// Shouldn't happen
		if (policies == null)
			return false;
		try {
			// Decode string
			policies = URLDecoder.decode(policies, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			System.err.println("Error: policy edit submit encode");
		}
		// Clear list and "modify"
		proxyServer.policyList.clear();
		String[] policyArr = policies.split(CRLF);
		for (String policy : policyArr) {
			if (!policy.equalsIgnoreCase("") && !policy.equalsIgnoreCase(CRLF))
				proxyServer.policyList.add(policy);
		}
		return true;
	}

	/**
	 * This method save to policies file user changes
	 * 
	 * @param policyPath
	 */
	private void savePolicy(String policyPath) {
		File policyFile = new File(policyPath);
		try {
			// Set file size to 0
			PrintWriter writer = new PrintWriter(policyFile);
			for (String policy : proxyServer.policyList) {
				writer.write(policy + CRLF);
			}
			writer.close();
		} catch (FileNotFoundException e) {
			System.err.println("Error: Save policy file");
		}
	}
}