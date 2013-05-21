package com.aqua.sysobj.wireshark;


public class WindowsWireSharkTest extends WireSharkTest {

	@Override
	protected String getSUTTag() {
		return "wireSharkWindows";
	}
	
    @Override
	public void testGetCapFileAsText() throws Exception {
    	super.testGetCapFileAsText();
    }

}
