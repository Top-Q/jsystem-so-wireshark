package com.aqua.examples.wireshark;


import java.io.File;
import java.net.URL;

import junit.framework.SystemTestCase;

import org.apache.commons.io.FileUtils;

import com.aqua.wireshark.WireShark;

public class APCfFileAnalysis extends SystemTestCase {

	private static File apcFile = new File("beacon.apc");
	private WireShark  wireShark;
	@Override
	public void setUp() throws Exception {
		if (!apcFile.exists()){
			URL url = getClass().getResource("/com/aqua/examples/wireshark/beacon.apc");
			FileUtils.copyURLToFile(url,apcFile);
		}
		wireShark = (WireShark)system.getSystemObject("wireSharkWindows");
	}
	

	/**
	 */
	public void testVisitApcFile() throws Exception {
		wireShark.setCaptureFileName("beacon.apc");
		wireShark.setCaptureFilesDirectoryName(new File("./").getAbsolutePath());
		wireShark.setPacketTreeOutput(true);
		wireShark.convertCapFileToTextFile("beacon.txt");
	}

}
