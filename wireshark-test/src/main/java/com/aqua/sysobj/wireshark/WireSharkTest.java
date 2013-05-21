package com.aqua.sysobj.wireshark;

import java.io.File;
import java.io.FileInputStream;
import java.util.zip.ZipInputStream;

import junit.framework.SystemTestCase;

import com.aqua.wireshark.WireShark;

public abstract class WireSharkTest extends SystemTestCase {

    private WireShark wireShark;

    @Override
	public void setUp() throws Exception {
    	wireShark = (WireShark) system.getSystemObject(getSUTTag());
    }

    /**
     */
    public void testStartAndStop() throws Exception {
	sniffExample(50, 300000, 100, "", "", false);
	File f = getWireShark().getCaptureFile(wireShark.getCaptureFileName(), true, false, false);
	assertTrue(f.exists());
	assertTrue(f.delete());
    }

    /**
         * 
         */
    public void testStartAndStopWithTestAgainstObject() throws Exception {
	Object res = sniffExample(10, 30000, 20, "", "", true);
	assertTrue(res != null);
	assertTrue(res.toString().indexOf("Arrival Time:") > -1);
    }

    /**
         * 
         */
    public void testFilterCapFile() throws Exception {
	getWireShark().setReadFilter("");
	getWireShark().filterCaptureFile("testFilterCapFile.cap");
	File f = getWireShark().getCaptureFile("testFilterCapFile.cap", false, false, false);
	assertTrue(f.exists());
	assertTrue(f.delete());

    }

    /**
         * 
         */
    public void testFilterCapFileWithName() throws Exception {
	getWireShark().setReadFilter("");
	getWireShark().filterCaptureFile("testFilterCapFile.cap", "testFilterCapFileWithName.cap");
	File f = getWireShark().getCaptureFile("testFilterCapFileWithName.cap", false, false, false);
	assertTrue(f.exists());
	assertTrue(f.delete());

    }

    /**
         * 
         */
    public void testFilterCapFileAndSetTestAgainstObject() throws Exception {
	getWireShark().setReadFilter("");
	getWireShark().filterCaptureFileAndSetTestAgainstObject(getWireShark().getCaptureFileName());
    }

    public void testGetCapFile() throws Exception {
    	File f = getWireShark().getCaptureFile(getWireShark().getCaptureFileName(), false, false, false);
    	assertTrue(f.exists());
    	assertTrue(f.delete());
    }

    /**
         * 
         */
    public void testGetCapFileAsText() throws Exception {
	File f = getWireShark().getCaptureFile(getWireShark().getCaptureFileName(), false, false, true);
	assertTrue(f.exists());
	assertTrue(f.getName().endsWith(".txt"));
	assertTrue(f.delete());
    }

    /**
         * 
         */
    public void testGetCapFileAsZip() throws Exception {
	File f = getWireShark().getCaptureFile(getWireShark().getCaptureFileName(), false, true, false);
	assertTrue(f.exists());
	assertTrue(f.getName().endsWith(".zip"));
	ZipInputStream stream = new ZipInputStream(new FileInputStream(f));
	assertTrue(stream.available() > 0);
	stream.close();
	assertTrue(f.delete());
    }

    /**
         * 
         */
    public void testGetCapFileDelete() throws Exception {
	File f = getWireShark().getCaptureFile("testFilterCapFile.cap", true, true, false);
	assertTrue(f.exists());
	assertTrue(f.delete());
	try {
	    getWireShark().getCaptureFile("testFilterCapFile.cap", true, true, false);
	    assertTrue("Get file after file deletion succeeded. File was not deleted", false);
	} catch (Exception e) {
	}

    }

    private Object sniffExample(int numOfPuckets, int fileSize, int captureDuration, String captureFilter,
	    String readFilter, boolean standardOutput) throws Exception {
	report.step("Pre Start Configurations");
	getWireShark().setCaptureFilter(captureFilter);
	getWireShark().setNumberOfPacketsToCapture(numOfPuckets);
	getWireShark().setCaptureDuration(captureDuration);
	getWireShark().setMaxFileSize(fileSize);

	// Start should be called after all running conifguration was done
	getWireShark().start();
	Thread.sleep(15000);
	report.step("Pre Stop Configurations");
	getWireShark().setReadFilter(readFilter);
	getWireShark().setPacketTreeOutput(true);// Example, it is true
	// by default
	getWireShark().setDumpToScreen(standardOutput);
	// Stop should be called AFTER all results configuration was set
	getWireShark().stop();
	return getWireShark().getTestAgainstObject();
    }

    protected int getIndex() {
	return 0;
    }

    private WireShark getWireShark() {
	return wireShark;
    }

    abstract protected String getSUTTag();

}