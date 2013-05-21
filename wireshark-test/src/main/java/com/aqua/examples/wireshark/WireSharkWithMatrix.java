package com.aqua.examples.wireshark;


import com.aqua.wireshark.WireSharkManager;

import junit.framework.SystemTestCase;

public class WireSharkWithMatrix extends SystemTestCase {

	private WireSharkManager manager;
	@Override
	public void setUp() throws Exception {
		manager = (WireSharkManager)system.getSystemObject("wireSharkManager");
	}
	
	/**
	 * Kick start/Example for analysing cap file with PacketCapture entity.
	 * In order for this example to work please copy
	 *  jpcap.dll to project folder.
	 */
	public void testActivateWireSharkWithMatrix() throws Exception {
		manager.wireSharkManagers[0].wireSharks[0].start();
		sleep(5000);
		manager.wireSharkManagers[0].wireSharks[0].stop();
		manager.wireSharkManagers[0].wireSharks[0].setPacketTreeOutput(true);
		manager.wireSharkManagers[0].wireSharks[0].setReadFilter("");
		manager.wireSharkManagers[0].wireSharks[0].filterCaptureFileAndSetTestAgainstObject(manager.wireSharkManagers[0].wireSharks[0].getCaptureFileName()); 	
		assertNotNull(manager.wireSharkManagers[0].wireSharks[0].getTestAgainstObject());
		
	}
}
