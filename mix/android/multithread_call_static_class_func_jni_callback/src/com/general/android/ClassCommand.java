package com.general.android;

public class ClassCommand {
	
	public static ClassCommand getInstance()
	{
		return new ClassCommand();
	}
	
	public static Object getInstanceObject()
	{
		return ClassCommand.getInstance(); 
	}
	
	public byte[] functionMember(byte[] data, int index)
	{
		return data.clone();
	}
	
	public static byte[] functionStatic(byte[] data, int index)
	{
		return data.clone();
	}

}
