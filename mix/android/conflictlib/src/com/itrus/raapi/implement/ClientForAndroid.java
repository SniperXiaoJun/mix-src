package com.itrus.raapi.implement;

public class ClientForAndroid {
	static {
		try {
			System.loadLibrary("O_AllA");
			System.loadLibrary("O_AllB");
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}
	}

	static public native int LOGB();
	static public native int LOGA();
}
