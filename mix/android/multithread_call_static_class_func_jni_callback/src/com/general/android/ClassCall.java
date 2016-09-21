package com.general.android;

public class ClassCall {
	
	static {
		try {
			System.loadLibrary("SoftToken");
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}
	}
	
	static public native void fucntioncthread();
	
	static public native void fucntionc();
}
