package com.general.android.LibConflict;

import android.widget.EditText;
import java.util.*;
import android.os.Bundle;
import com.itrus.raapi.implement.*;
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

import com.general.android.tools.FileHelper;

public class LibConflict extends Activity implements OnClickListener,
		android.content.DialogInterface.OnClickListener {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_test4_tian_wei);

		timer = new Timer();

		ctx = this;

		handler = new Handler() {
			public void handleMessage(Message msg) {
				switch (msg.what) {
				case 1:
					Toast.makeText(ctx, "正在使用测试LICENSE!", Toast.LENGTH_LONG)
							.show();
					;
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

	Button buttonTest;

	int iRet = 0;
	String strRet;
	String strErr;
	String[] strArray;
	String appPath;


	Context ctx;
	Handler handler;
	Timer timer;
	TimerTask task;

	public void setLocalVar() {

		buttonTest = (Button) findViewById(R.id.buttonTest);
		buttonTest.setOnClickListener(this);


		editText = (EditText) findViewById(R.id.editText);

		if (editText instanceof android.widget.EditText) {
			//editText.setCursorVisible(false); // 设置输入框中的光标不可见
			//editText.setFocusable(false); // 无焦点
			//editText.setFocusableInTouchMode(false); // 触摸时也得不到焦点
		}

	}

	public void onClick(DialogInterface dialog, int which) {
	}

	public void onClick(View arg0) {

		if (arg0 == buttonTest) {

			int i = 0;

			String strP10 = "";

			FileHelper fileHelper = new FileHelper(this);
			
			ClientForAndroid.LOGA();
			ClientForAndroid.LOGB();

			for (i = 0; i < 10000; i++) {
				ClientForAndroid.LOGA();
				ClientForAndroid.LOGB();
			}

			editText.setText("当前次数：" + i);
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.test4_tian_wei, menu);
		return true;
	}

}
