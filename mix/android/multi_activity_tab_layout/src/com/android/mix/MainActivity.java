package com.android.mix;

import com.android.mix.R;
import com.android.mix.view.tab.FragmentAndFragmentManagerActivity;
import com.android.mix.view.tab.MainFragmentActivity;
import com.android.mix.view.tab.MixTabActivity;
import com.android.mix.view.tab.TabHostAndTabWidgetActivity;
import com.android.mix.view.tab.ViewPagerAndFragmentAndFragmentPagerAdapterActivity;
import com.android.mix.view.tab.ViewPagerAndPageAdapterActivity;
import com.android.mix.view.tab.ViewPagerAndPagerTitleStripActivity;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;

/**
 * 
 * @author jacksen
 * 
 */
public class MainActivity extends Activity implements OnClickListener {

	private Button btn1, btn2, btn3, btn4, btn5, btn6, btn7;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		init();
	}

	private void init() {
		btn1 = (Button) findViewById(R.id.btn1);
		btn2 = (Button) findViewById(R.id.btn2);
		btn3 = (Button) findViewById(R.id.btn3);
		btn4 = (Button) findViewById(R.id.btn4);
		btn5 = (Button) findViewById(R.id.btn5);
		btn6 = (Button) findViewById(R.id.btn6);
		btn7 = (Button) findViewById(R.id.btn7);

		btn1.setOnClickListener(this);
		btn2.setOnClickListener(this);
		btn3.setOnClickListener(this);
		btn4.setOnClickListener(this);
		btn5.setOnClickListener(this);
		btn6.setOnClickListener(this);
		btn7.setOnClickListener(this);
	}

	@Override
	public void onClick(View v) {
		Intent intent = new Intent();
		switch (v.getId()) {
		case R.id.btn1:
			intent.setClass(this, ViewPagerAndPageAdapterActivity.class);
			break;
		case R.id.btn2:
			intent.setClass(this, FragmentAndFragmentManagerActivity.class);
			break;
		case R.id.btn3:
			intent.setClass(this, ViewPagerAndFragmentAndFragmentPagerAdapterActivity.class);
			break;
		case R.id.btn4:
			intent.setClass(this, TabHostAndTabWidgetActivity.class);
			break;
		case R.id.btn5:
			intent.setClass(this, ViewPagerAndPagerTitleStripActivity.class);
			break;
		case R.id.btn6:
			intent.setClass(this, MainFragmentActivity.class);
			break;
		case R.id.btn7:
			intent.setClass(this, MixTabActivity.class);
			break;
		}
		startActivity(intent);
	}

}
