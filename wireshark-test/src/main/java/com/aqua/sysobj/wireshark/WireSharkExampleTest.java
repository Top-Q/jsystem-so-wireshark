package com.aqua.sysobj.wireshark;

import junit.framework.SystemTestCase;

import com.aqua.wireshark.WireShark;

public class WireSharkExampleTest extends SystemTestCase {

    private WireShark wireShark;

    @Override
	public void setUp() throws Exception {
    	wireShark = (WireShark) system.getSystemObject("wireSharkWindows");
    }

    


	public void testStartAndStop1() throws Exception{
		
    	report.step("Step 1: Pre Start Configurations");
    	wireShark.setCaptureFilter("");
    	wireShark.setNumberOfPacketsToCapture(15);
    	wireShark.setMaxFileSize(15000);
    	wireShark.setCaptureFileName("tmpWireShark.cap");
    	// Start should be called after all running conifguration was done
    	wireShark.start();
    	
    	report.step("Pre Stop Configurations");
    	wireShark.setReadFilter("");
    	wireShark.setPacketTreeOutput(false);
    	// Stop should be called after all results configuration was set
    	wireShark.stop();
    	
    	report.step("Filters the file and sets filter results to wireshark's test against object");
    	wireShark.setPacketTreeOutput(true);
    	wireShark.setReadFilter("");
    	wireShark.filterCaptureFileAndSetTestAgainstObject(wireShark.getCaptureFileName()); 	
	    
    	report.step("New capture file");
    	wireShark.setReadFilter("");
		wireShark.filterCaptureFile("tmpWireShark.cap", "newFilterCapFile.cap");
    	
		report.step("Get capture file");
		wireShark.getCaptureFile("newFilterCapFile.cap", false, false, true);
		wireShark.getCaptureFile("newFilterCapFile.cap", false, true, false);
		wireShark.getCaptureFile("newFilterCapFile.cap", true, false, false);
		
//		restores all the wireShark params to default
		wireShark.restoreAllParams();
	}

	public void testStartAndStop2() throws Exception{
		
		report.step("Step 2: Pre Start Configurations");
    	wireShark.start("eth0", "tcp", 5);
    	
    	report.step("Pre Stop Configurations");
    	wireShark.stop("", true);
    	
    	report.step("Filters the file and sets filter results to wireshark's test against object");
    	wireShark.filterCaptureFileAndSetTestAgainstObject("temp.cap", "", false); 	
    	
    	report.step("New capture file");
    	wireShark.setPacketTreeOutput(true);
		wireShark.filterCaptureFile("tmpWireShark.cap", "newFilterCapFile.cap");
		
		report.step("Get capture file");
		wireShark.getCaptureFile("newFilterCapFile.txt", true, false, false);
	}
	
}