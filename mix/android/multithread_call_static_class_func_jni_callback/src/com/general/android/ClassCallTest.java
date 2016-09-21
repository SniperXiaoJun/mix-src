package com.general.android;

import android.widget.EditText;

import java.util.*;

import android.os.Bundle;
import android.content.*;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;
import android.widget.*;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.os.*;
import android.app.AlertDialog;

import com.general.android.R;
import com.general.android.tools.FileHelper;

public class ClassCallTest extends Activity implements OnClickListener,
		android.content.DialogInterface.OnClickListener {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		timer = new Timer();
		
		fileHelper = new FileHelper(this);

		ctx = this;

		handler = new Handler() {
			public void handleMessage(Message msg) {
				switch (msg.what) {
				case 1:
//					Toast.makeText(ctx, "正在使用测试LICENSE!", Toast.LENGTH_LONG)
//							.show();
//					;
					break;
	            case 2:  
	            	editText.setText(strRet);
	                break; 
	             default:
	                break;
				}
				
 
				
				super.handleMessage(msg);
			}
		};
		task = new TimerTask() {
			public void run() {
				Message message = new Message();
				message.what = 1;
				handler.sendMessage(message);
			}
		};

		setLocalVar();
	}

	EditText editText;

	Button buttonThreadMain;
	Button buttonThreadC;
	Button buttonThreadJava;

	int iRet = 0;
	String strRet;
	String strErr;
	String[] strArray;
	String appPath;

	int op;

	Context ctx;
	Handler handler;
	Timer timer;
	TimerTask task;
	
	FileHelper fileHelper;

	public void setLocalVar() {
		
		

		buttonThreadJava = (Button) findViewById(R.id.buttonThreadJava);
		buttonThreadJava.setOnClickListener(this);
		
		buttonThreadC = (Button) findViewById(R.id.buttonThreadC);
		buttonThreadC.setOnClickListener(this);
		
		buttonThreadMain = (Button) findViewById(R.id.buttonThreadMain);
		buttonThreadMain.setOnClickListener(this);
		
		editText = (EditText) findViewById(R.id.editText);

		if (editText instanceof android.widget.EditText) {
			//editText.setCursorVisible(false); // 设置输入框中的光标不可见
			//editText.setFocusable(false); // 无焦点
			//editText.setFocusableInTouchMode(false); // 触摸时也得不到焦点
		}

		op = 0;
	}

	public void onClick(DialogInterface dialog, int which) {

		if (0 == op) {
			
		} else if (3 == op) {
			
		} else {
			
		}
	}

	public void onClick(View arg0) {

		if (arg0 == buttonThreadJava) {

			Thread thread=new Thread(new Runnable()  
	        {  
	            @Override  
	            public void run()  
	            {  
	            	try{
	            		ClassCall.fucntionc();
	            	}
	            	catch (Exception e) {
						e.printStackTrace();
						editText.append(e.toString());
					}
	            }  
	        });  
	        thread.start();  
			
			editText.setText("buttonThreadJava");
		} else if (arg0 == buttonThreadC) {
			ClassCall.fucntioncthread();
			editText.setText("buttonThreadC");
		} else if (arg0 == buttonThreadMain) {
			 ClassCall.fucntionc();

			editText.setText("buttonThreadMain");
		} 
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.test4_tian_wei, menu);
		return true;
	}

}
