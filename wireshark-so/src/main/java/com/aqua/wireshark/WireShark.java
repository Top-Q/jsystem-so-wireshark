package com.aqua.wireshark;

import java.io.File;

import jsystem.framework.system.SystemObjectImpl;

import com.aqua.stations.CliApplicationExtension;
import com.aqua.stations.Station;
import com.aqua.stations.StationsFactory;
import com.aqua.stations.StationDefaultImpl;
import com.aqua.sysobj.conn.CliApplication;

/**
 * SystemObject for using TShark network protocol analyzer.<br>
 * For more information about the WireShart application please read package.
 * <br>
 * <b><u>Using the <code>WireShark</code> system object:</u></b><br>
 * 1. Configure pre run parameters:(or use SUT file)<br>
 * 2. Start capturing traffic. {@link #start()}<br>
 * 3. Run traffic( not done using this system object)<br>
 * 3. Stop capturing traffic (and possibly get capture results to 'test against
 * object') {@link stop()}<br>
 * 4. Filter capture file as needed and create new capture file(s) with filter
 * results<br>
 * {@link #filterCaptureFile(String)},{@link #filterCaptureFile(String, String)},{@link #filterCaptureFileAnSetTestAgainstObject(String)}<br>
 * 5. Fetch capture file from WireShark machine.
 * {@link #getCaptureFile(String, boolean, boolean, boolean)}<br>
 * <br>
 * <u>Note:</u> WireShark is not thread safe.<br>
 * <br>
 * <b><u><code>WireShark</code> implementation details:</u></b><br>
 * The <code>WireShark</code> system object uses the {@link Station} system
 * object to communicate with remote machine.<br>
 * Other relevant system objects:{@link CliApplication},{@link com.aqua.filetransfer.ftp.FTPFileTransfer}
 * <br>
 * 
 */
public class WireShark extends SystemObjectImpl {

	/**
	 * Holds wiresharks default values.
	 */
	private WireShark wireSharkDefaultValues;

	private StationDefaultImpl station;

	// CLI application is public so the user will be able to initiate it from SUT
	public CliApplication cliApplication;

	// the host on which the wireshark application is running.
	private String host;

	private String localHostExternalName;

	// The operating system of the host on which the wireshark is running.
	private String operatingSystem = StationsFactory.OPERATING_SYSTEM_LINUX;

	// The protocol to communicate with the wireshark machine (telnet or ssh)
	private String protocol;

	// The port for communication
	private int port;

	// User for authentication
	private String user;

	// Password for authentication
	private String password;

	// Default valuse to integer
	private static final int NO_VALUE = -1;

	// The Default file Size
	private static final int DEFAULT_MAX_FILE_SIZE = 20000; // in KB

	// The Application path and name stated in SUT file
	private String applicationName = "tshark"; // Default is tshark

	// the networking interface to sniff on.
	private String interfaceName;

	// Run time filter (results will be saved AFTER filtering)
	private String captureFilter;

	// Filter capture result from already existing capture file
	private String readFilter;

	// Directory path to the capture file
	private String captureFilesDirectoryName = ".";

	// Capture file name
	private String captureFileName = "temp.cap";
	
	// Write to file (-w) or redirect to file (using >)
	private boolean writeToFile = true;

	// The application will stop running when file size is >= maxFileSize KB
	private int maxFileSize = DEFAULT_MAX_FILE_SIZE;

	// The number of packets to capture
	private int numberOfPacketsToCapture = NO_VALUE;

	// The number of seconds to capture
	private int captureDuration = NO_VALUE;

	// Timeout for CLI stop command
	private long timeout = 30000;

	// If true, when stopping tshark, cap file is filtered with read filter
	// and dumped to the standard output
	private boolean dumpToScreen = true;

	// (-V)Show the retrieved data from file in a packet tree way, set to
	// false
	// will show only the summary
	private boolean packetTreeOutput = false;

	// Any additional command arguments/flags/whatever
	private	String additionalCommand = null;
	
	/**
	 * Initializes WireShark.<br>
	 * Verifies that a connection from tests hosts machine to WireShark machine
	 * and back can be established.
	 */
	@Override
	public void init() throws Exception {
		super.init();
		// cli application was initiated by the user in the sut
		if (cliApplication != null) {
			// if operating system was not supplied by user selecting NA os. for
			// stations
			station = StationsFactory.createStation(cliApplication.conn.cli.getHost(), getOperatingSystem(),
					cliApplication.conn.cli.getProtocol(), cliApplication.conn.cli.getUser(), cliApplication.conn.cli
							.getPassword(), cliApplication.conn.cli.getPrompts());
			if (getLocalHostExternalName() != null) {
				station.setLocalHostExternalName(getLocalHostExternalName());
			}
			station.init();
		} else {
			station = StationsFactory.createStation(getHost(), getOperatingSystem(), getProtocol(), getUser(),
					getPassword(), null);
			if (getLocalHostExternalName() != null) {
				station.setLocalHostExternalName(getLocalHostExternalName());
			}
			station.init();
			cliApplication = station.getCliSession(false);
		}
		setDefaultParams();
	}

	/**
	 * Starts WireShark sniffig. Relevant members: {@link #interfaceName},{@link #maxFileSize},
	 * {@link #captureFilter},{@link #captureDuration},{@link #captureFileName},
	 * {@link #captureFilesDirectoryName},{@link #numberOfPacketsToCapture},
	 */
	public void start() throws Exception {
		StringBuffer startCommand = appendCapturCommand(buildTSharkCommand());
		cliApplication.cliCommand("");
		WireSharkCliCommand cmd = new WireSharkCliCommand(startCommand.toString());
		cmd.setPromptString("Capturing on");
		cmd.setTimeout(2000);
		cmd.setIgnoreErrors(true);
		cliApplication.handleCliCommand("Start Capture", cmd);
		setTestAgainstObject(cliApplication.getTestAgainstObject());
	}

	/**
	 * This function set the params it gets, and call the start() function
	 * 
	 * @param interfaceName -
	 *            interface name
	 * @param captureFilter -
	 *            capture filter
	 * @param packetsToCapture -
	 *            packets to capture
	 * @throws Exception
	 */
	public void start(String interfaceName, String captureFilter, int packetsToCapture) throws Exception {
		setInterfaceName(interfaceName);
		setCaptureFilter(captureFilter);
		setNumberOfPacketsToCapture(packetsToCapture);
		start();
	}

	/**
	 * This function set the params it gets, and call the start() function
	 * 
	 * @param interfaceName -
	 *            interface name
	 * @param captureFilter -
	 *            capture filter
	 * @throws Exception
	 */
	public void start(String interfaceName, String captureFilter) throws Exception {
		setInterfaceName(interfaceName);
		setCaptureFilter(captureFilter);
		start();
	}

	/**
	 * This function set the params it gets, and call the start() function
	 * 
	 * @param captureFilter -
	 *            capture filter
	 * @throws Exception
	 */
	public void start(String captureFilter) throws Exception {
		setCaptureFilter(captureFilter);
		start();
	}

	/**
	 * Stops WireShark capture. If WireShark is configured to return capture to
	 * standard output ({@link #dumpToScreen}, the stop operation sets the
	 * 'testAgainstObject' with capture result.
	 */
	public void stop() throws Exception {
		WireSharkCliCommand cmd = new WireSharkCliCommand(new String(new byte[] { '\u0003' }));
		cmd.setTimeout(getTimeout());
		cliApplication.handleCliCommand("Stop Capture", cmd);
		setTestAgainstObject(cliApplication.getTestAgainstObject());
		if (getDumpToScreen()) {
			StringBuffer buf = appendFilterCommand(buildTSharkCommand(), getCaptureFileName());
			cmd = new WireSharkCliCommand(buf.toString());
			cmd.setTimeout(getTimeout());
			cliApplication.handleCliCommand("Read from file", cmd);
			setTestAgainstObject(cliApplication.getTestAgainstObject());
		}
	}

	/**
	 * This function set the params it gets, and call the stop() function
	 * 
	 * @param readFilter
	 * @param packetTreeOutput
	 * @throws Exception
	 */
	public void stop(String readFilter, boolean packetTreeOutput) throws Exception {
		stop(readFilter, packetTreeOutput, timeout);
	}

	public void stop(String readFilter, boolean packetTreeOutput, long timeout) throws Exception {
		setTimeout(timeout);
		setReadFilter(readFilter);
		setPacketTreeOutput(packetTreeOutput);
		stop();
	}

	/**
	 * This function set the params it gets, and call the stop() function
	 * 
	 * @param captureFileName -
	 *            The captured file name
	 * @param readFilter
	 * @param packetTreeOutput
	 * @throws Exception
	 */
	public void stop(String captureFileName, String readFilter, boolean packetTreeOutput) throws Exception {
		stop(captureFileName, readFilter, packetTreeOutput, timeout);
	}

	public void stop(String captureFileName, String readFilter, boolean packetTreeOutput, long timeout)
			throws Exception {
		setTimeout(timeout);
		setReadFilter(readFilter);
		setPacketTreeOutput(packetTreeOutput);
		setCaptureFileName(captureFileName);
		stop();
	}

	/**
	 * Filters the captured cap file and creates a new capture file with
	 * filtered traffic. Relevant members: {@link #captureFileName},{@link #captureFilesDirectoryName},
	 * {@link #readFilter}
	 */
	public void filterCaptureFile(String newFileName) throws Exception {
		filterCaptureFile(getCaptureFileName(), newFileName);
	}

	/**
	 * Filters the <code>captureFileName</code> and creates a new capture file
	 * with filtered traffic.
	 * 
	 * Relevant members: {@link #captureFilesDirectoryName},
	 * {@link #readFilter}
	 */
	public void filterCaptureFile(String captureFileName, String newFileName) throws Exception {
		StringBuffer buf = appendFilterCommand(buildTSharkCommand(), captureFileName);
		buf.append(" -w " + FileUtils.wrapPathWithApostrophe(getCaptureFilesDirectoryName() + "/" + newFileName));
		WireSharkCliCommand cmd = new WireSharkCliCommand(buf.toString());
		CliApplicationExtension.handleCommandAndVerifyEmptyOutput(cliApplication, "Filtering capture file", cmd);
	}

	/**
	 * Filters <code>captureFileName</code> and sets filter results to
	 * Wireshark's test against object.
	 */
	public void filterCaptureFileAndSetTestAgainstObject(String captureFileName) throws Exception {
		StringBuffer buf = appendFilterCommand(buildTSharkCommand(), captureFileName);
		WireSharkCliCommand cmd = new WireSharkCliCommand(buf.toString());
		cliApplication.handleCliCommand("Filtering capture file", cmd);
		setTestAgainstObject(cliApplication.getTestAgainstObject());
	}

	/**
	 * This function set the params it gets, and call the
	 * filterCaptureFileAndSetTestAgainstObject(captureFileName) function
	 */
	public void filterCaptureFileAndSetTestAgainstObject(String captureFileName, String readFilter,
			boolean packetTreeOutput) throws Exception {
		setReadFilter(readFilter);
		setPacketTreeOutput(packetTreeOutput);
		filterCaptureFileAndSetTestAgainstObject(captureFileName);
	}

	/**
	 * Fetches capture file from wireshark's machine. Relevant members:{@link #captureFilesDirectoryName}
	 * 
	 * @param fileName -
	 *            name of capture file to fetch.
	 * @param removeFile -
	 *            if true file is removed from wireshark machine.
	 * @param zipFile -
	 *            if true the fetched file is zipped.The name of the returned
	 *            file is created by replacing the suffix of
	 *            <code>fileName</code> to .zip.
	 * @param asText -
	 *            when true capture file is converted to text file and the text
	 *            file is fetched from the wireshark's machine.
	 */
	public File getCaptureFile(String fileName, boolean removeFile, boolean zipFile, boolean asText) throws Exception {
		if (asText) {
			fileName = convertCapFileToTextFile(fileName);
		}
		File captureFile = new File(getCaptureFilesDirectoryName(), fileName);
		File retFile = new File(fileName);
		station.copyFileFromRemoteMachineToLocalMachine(captureFile, retFile);
		station.closeFileTransferSession();

		if (removeFile) {
			station.deleteFile(captureFile.getPath());
		}

		if (zipFile) {
			File zipFileObj = com.aqua.wireshark.FileUtils.fileToZipFile(retFile);
			retFile.delete();
			return zipFileObj;
		}

		return retFile;
	}

	/**
	 * Converts cap/APC file to txt file. Relevant members:
	 * {@link #captureFilesDirectoryName},{@link #getCaptureFileName()}
	 */
	public String convertCapFileToTextFile(String name) throws Exception {
		String newName = FileUtils.changeFileNameSuffix(name, "txt");
		StringBuffer buf = appendFilterCommand(buildTSharkCommand(), getCaptureFileName());
		buf.append(" > " + FileUtils.wrapPathWithApostrophe(getCaptureFilesDirectoryName() + "/" + newName));
		cliApplication.cliCommand("");
		WireSharkCliCommand cmd = new WireSharkCliCommand(buf.toString());
		CliApplicationExtension.handleCommandAndVerifyEmptyOutput(cliApplication, "Converted capture file to txt file",	cmd);
		return newName;
	}

	/***************************************************************************
	 * WireShark commands manipulation methods
	 */
	private StringBuffer buildTSharkCommand() {
		StringBuffer buf = new StringBuffer();
		if (getOperatingSystem().equals("windows")) {
			// In order to be able to use redirection (>) we must run the "cmd" and
			// hand it the tshark as an argument.
			buf.append("cmd /c ");
		}
		buf.append(getApplicationName());		
		return buf;
	}

	private StringBuffer appendCapturCommand(StringBuffer buf) {
		buf.append(" -i " + getInterfaceName());
		if (getCaptureFilter() != null && ! "".equals(getCaptureFilter().trim())) {
			buf.append(" -f \"" + getCaptureFilter() + "\"");
		}
		// Set Capturing limit (by number of packets, number of seconds,
		// or no limit apart from the above max file size
		if (getNumberOfPacketsToCapture() != NO_VALUE) {
			buf.append(" -c " + getNumberOfPacketsToCapture());
		} else if (getCaptureDuration() != NO_VALUE) {
			buf.append(" -a duration:" + getCaptureDuration());
		}
		if (getAdditionalCommand() != null) {
			buf.append(" " + getAdditionalCommand() + " ");
		}
		if (isWriteToFile()) {
			// If writing into file, max file size is always appended
			buf.append(" -a filesize:" + getMaxFileSize());
			buf.append(" -w " + FileUtils.wrapPathWithApostrophe(getCaptureFilesDirectoryName() + "/" + getCaptureFileName()));
		} else {
			buf.append(" > " + FileUtils.wrapPathWithApostrophe(getCaptureFilesDirectoryName() + "/" + getCaptureFileName()));			
		}
		return buf;
	}

	/**
	 * Closes wire shark sessions.
	 */
	@Override
	public void close() {
		station.close();
		super.close();
	}

	private StringBuffer appendFilterCommand(StringBuffer buf, String name) {
		if (isPacketTreeOutput()) {
			buf.append(" -V ");
		}
		buf.append(" -r " + FileUtils.wrapPathWithApostrophe(getCaptureFilesDirectoryName() + "/" + name));
		if (getReadFilter() != null && !"".equals(getReadFilter())) {
			buf.append(" -R \"" + getReadFilter() + "\"");
		}
		if (getAdditionalCommand() != null) {
			buf.append(" " + getAdditionalCommand());
		}
		return buf;
	}

	/**
	 * This function restores to default params
	 */
	public void restoreStartParams() throws Exception {
		setInterfaceName(wireSharkDefaultValues.getInterfaceName());
		setCaptureFileName(wireSharkDefaultValues.getCaptureFileName());
		setCaptureFilesDirectoryName(wireSharkDefaultValues.getCaptureFilesDirectoryName());
		setCaptureDuration(wireSharkDefaultValues.getCaptureDuration());
		setCaptureFilter(wireSharkDefaultValues.getCaptureFilter());
		setMaxFileSize(wireSharkDefaultValues.getMaxFileSize());
		setNumberOfPacketsToCapture(wireSharkDefaultValues.getNumberOfPacketsToCapture());
		setAdditionalCommand(wireSharkDefaultValues.getAdditionalCommand());
	}

	/**
	 * This function restores to default params
	 */
	public void restoreStopParams() throws Exception {
		setCaptureFilesDirectoryName(wireSharkDefaultValues.getCaptureFilesDirectoryName());
		setCaptureFileName(wireSharkDefaultValues.getCaptureFileName());
		setDumpToScreen(wireSharkDefaultValues.getDumpToScreen());
		setPacketTreeOutput(wireSharkDefaultValues.isPacketTreeOutput());
		setReadFilter(wireSharkDefaultValues.getReadFilter());
		setTimeout(wireSharkDefaultValues.getTimeout());
	}

	/**
	 * 
	 * @throws Exception
	 */
	public void restoreAllParams() throws Exception {
		restoreStartParams();
		restoreStopParams();
	}

	/**
	 * Gets parameters values from this object and saves them in the default
	 * values object.
	 */
	private void setDefaultParams() {
		wireSharkDefaultValues = new WireShark();
		wireSharkDefaultValues.setApplicationName(getApplicationName());
		wireSharkDefaultValues.setCaptureDuration(getCaptureDuration());
		wireSharkDefaultValues.setCaptureFileName(getCaptureFileName());
		wireSharkDefaultValues.setCaptureFilesDirectoryName(getCaptureFilesDirectoryName());
		wireSharkDefaultValues.setCaptureFilter(getCaptureFilter());
		wireSharkDefaultValues.setDumpToScreen(getDumpToScreen());
		wireSharkDefaultValues.setInterfaceName(getInterfaceName());
		wireSharkDefaultValues.setMaxFileSize(getMaxFileSize());
		wireSharkDefaultValues.setNumberOfPacketsToCapture(getNumberOfPacketsToCapture());
		wireSharkDefaultValues.setPacketTreeOutput(isPacketTreeOutput());
		wireSharkDefaultValues.setReadFilter(getReadFilter());
		wireSharkDefaultValues.setTimeout(getTimeout());
		wireSharkDefaultValues.setAdditionalCommand(getAdditionalCommand());
	}

	/**
	 * 
	 * Setters & Getters
	 * 
	 */

	public String getApplicationName() {
		return applicationName;
	}

	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	public String getCaptureFileName() {
		return captureFileName;
	}

	public void setCaptureFileName(String captureFileName) {
		this.captureFileName = captureFileName;
	}

	public String getCaptureFilesDirectoryName() {
		return captureFilesDirectoryName;
	}

	public void setCaptureFilesDirectoryName(String captureFilesDirectoryName) {
		this.captureFilesDirectoryName = captureFilesDirectoryName;
	}

	public String getCaptureFilter() {
		return captureFilter;
	}

	public void setCaptureFilter(String captureRealTimeFilter) {
		this.captureFilter = captureRealTimeFilter;
	}

	public String getInterfaceName() {
		return interfaceName;
	}

	public void setInterfaceName(String interfaceName) {
		this.interfaceName = interfaceName;
	}

	public int getMaxFileSize() {
		return maxFileSize;
	}

	public void setMaxFileSize(int maxFileSize) {
		this.maxFileSize = maxFileSize;
	}

	public int getNumberOfPacketsToCapture() {
		return numberOfPacketsToCapture;
	}

	public void setNumberOfPacketsToCapture(int packetsToCapture) {
		this.numberOfPacketsToCapture = packetsToCapture;
	}

	public boolean getDumpToScreen() {
		return dumpToScreen;
	}

	public void setDumpToScreen(boolean dumpToStandardOutput) {
		this.dumpToScreen = dumpToStandardOutput;
	}

	public boolean isPacketTreeOutput() {
		return packetTreeOutput;
	}

	public void setPacketTreeOutput(boolean packetTreeOutput) {
		this.packetTreeOutput = packetTreeOutput;
	}

	public String getReadFilter() {
		return readFilter;
	}

	public void setReadFilter(String readFilter) {
		this.readFilter = readFilter;
	}

	public int getCaptureDuration() {
		return captureDuration;
	}

	public void setCaptureDuration(int captureDuration) {
		this.captureDuration = captureDuration;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getOperatingSystem() {
		return operatingSystem;
	}

	public void setOperatingSystem(String operatingSystem) {
		this.operatingSystem = operatingSystem;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getLocalHostExternalName() {
		return localHostExternalName;
	}

	public void setLocalHostExternalName(String localHostExternalName) {
		this.localHostExternalName = localHostExternalName;
	}

	public long getTimeout() {
		return timeout;
	}

	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}
	
	public String getAdditionalCommand() {
		return additionalCommand;
	}

	public void setAdditionalCommand(String additionalCommand) {
		this.additionalCommand = additionalCommand;
	}

	public boolean isWriteToFile() {
		return writeToFile;
	}

	public void setWriteToFile(boolean writeToFile) {
		this.writeToFile = writeToFile;
	}
	
}
