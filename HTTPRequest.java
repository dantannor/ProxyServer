import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;

public class HTTPRequest {

	final static String SPACE = " ";
	final static String CONTENT_LENGTH = "content-length";
	final static String REFERER = "referer";
	final static String USER_AGENT = "user-agent";
	final static String CONTENT_TYPE = "content-type";
	final static String CHUNKED = "chunked";
	final static String TRANSFER_ENCODING = "transfer-encoding";
	final static String HOST = "host";

	private String method;
	private String file;
	private String version;
	private boolean isChunked;
	private boolean isImage;
	private boolean isIcon;
	private boolean isHtml;
	private int contentLength;
	private String referer;
	private String userAgent;
	private String requestLine;
	private String host;
	private HashMap<String, String> parameters;
	private String url;

	public HTTPRequest(String requestLine, HashMap<String, String> headers,
			HashMap<String, String> parameters) {

		this.parameters = new HashMap<>();

		// HTTP method
		method = requestLine.split(" ")[0];
		// HTTP requested file
		file = requestLine.split(" ")[1];
		url = requestLine.split(" ")[1];
		try {
			url = URLDecoder.decode(url, "UTF-8");
		} catch (UnsupportedEncodingException e1) {
			System.err.println("Error: decode url");
		}
		if (file.contains("?")) {
			try {
				String params[] = URLDecoder.decode(
						file.substring(file.indexOf('?') + 1), "UTF-8").split(
						"&");
				for (int i = 0; i < params.length; i++) {
					if (params[i].indexOf('=') != -1) {
						String key = params[i].substring(0,
								params[i].indexOf('='));
						String value = params[i].substring(params[i]
								.indexOf('=') + 1);
						if (!this.parameters.containsKey(key)) {
							this.parameters.put(key, value);
						}
					}
				}
				file = file.substring(0, file.indexOf('?'));
			} catch (UnsupportedEncodingException e) {
				System.err.println("Error: HTTPRequest decode");
			}
		}

		try {
			file = URLDecoder.decode(file, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			System.err.println("Error: HTTPRequest decode");
		}

		// This should be here to make sure that parameter that passes through
		// content
		// will not override parameters through request line.
		for (String key : parameters.keySet()) {
			if (!this.parameters.containsKey(key)) {
				this.parameters.put(key, parameters.get(key));
			}
		}

		// HTTP version
		version = requestLine.split(" ")[2];

		this.requestLine = getMethod() + SPACE + getFile() + SPACE
				+ getVersion();

		// file extension in order to check if the file is an image
		String fileExtenstion = file.substring(file.indexOf('.') + 1);
		if (fileExtenstion.equalsIgnoreCase("jpg")
				|| fileExtenstion.equalsIgnoreCase("gif")
				|| fileExtenstion.equalsIgnoreCase("bmp")
				|| fileExtenstion.equalsIgnoreCase("png")) {
			isImage = true;
		} else if (fileExtenstion.equalsIgnoreCase("ico")) {
			isIcon = true;
		} else if (fileExtenstion.equalsIgnoreCase("html")
				|| file.equalsIgnoreCase("")) {
			isHtml = true;
		}
		// Check if chunked
		if (headers.containsKey(CHUNKED)) {
			if (headers.get(CHUNKED).equalsIgnoreCase("yes")) {
				isChunked = true;
			} else {
				isChunked = false;
			}
		}
		// Content-Length header
		if (headers.containsKey(CONTENT_LENGTH))
			contentLength = Integer.parseInt(headers.get(CONTENT_LENGTH));
		// Referrer header
		if (headers.containsKey(REFERER))
			referer = headers.get(REFERER);
		// User-Agent header
		if (headers.containsKey(USER_AGENT))
			userAgent = headers.get(USER_AGENT);
		// Host header
		if (headers.containsKey(HOST))
			host = headers.get(HOST);

		// try {
		// url = URLDecoder.decode(url, "UTF-8");
		// } catch (UnsupportedEncodingException e) {
		// System.err.println("Error: HTTPRequest decode url");
		// }
	}

	public String getURL() {
		return this.url;
	}

	public String getMethod() {
		return this.method;
	}

	public String getFile() {
		return this.file;
	}

	public String getVersion() {
		return this.version;
	}

	public boolean isImage() {
		return this.isImage;
	}

	public int getContentLength() {
		return this.contentLength;
	}

	public String getReferer() {
		return this.referer;
	}

	public String getUserAgent() {
		return this.userAgent;
	}

	public String getHost() {
		return this.host;
	}

	public HashMap<String, String> getParameters() {
		return this.parameters;
	}

	public boolean isIcon() {
		return this.isIcon;
	}

	public boolean isHtml() {
		return this.isHtml;
	}

	public boolean isChunked() {
		return this.isChunked;
	}

	public String getRequestLine() {
		return this.requestLine;
	}
}
