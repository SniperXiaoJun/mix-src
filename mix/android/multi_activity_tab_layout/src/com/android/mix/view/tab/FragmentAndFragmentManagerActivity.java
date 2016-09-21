package com.android.mix.view.tab;

import com.android.mix.R;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentTransaction;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.LinearLayout;

/**
 * �ڶ���tab�����ʵ�ַ�ʽ-- ��Fragment + FragmentManager
 * 
 * @since 2015��1��12��
 * @author jacksen
 * 
 */
public class FragmentAndFragmentManagerActivity extends FragmentActivity implements OnClickListener {

	// ���ѡ�
	private LinearLayout tab1Layout, tab2Layout, tab3Layout;
	// Ĭ��ѡ�е�һ��tab
	private int index = 1;
	// fragment������
	private FragmentManager fragmentManager;
	// ���fragment
	private Fragment tab1Fragment, tab2Fragment, tab3Fragment;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_fragmentandfragmentmanager);
		fragmentManager = getSupportFragmentManager();
		init();
	}

	/**
	 * ��ʼ���ؼ�
	 */
	private void init() {
		tab1Layout = (LinearLayout) findViewById(R.id.tab1_layout);
		tab2Layout = (LinearLayout) findViewById(R.id.tab2_layout);
		tab3Layout = (LinearLayout) findViewById(R.id.tab3_layout);

		tab1Layout.setOnClickListener(this);
		tab2Layout.setOnClickListener(this);
		tab3Layout.setOnClickListener(this);
		//
		setDefaultFragment();
	}

	/**
	 * ����Ĭ����ʾ��fragment
	 */
	private void setDefaultFragment() {
		FragmentTransaction transaction = fragmentManager.beginTransaction();
		tab1Fragment = new Tab1Fragment();
		transaction.replace(R.id.content_layout, tab1Fragment);
		transaction.commit();
	}

	/**
	 *�л�fragment
	 * @param newFragment
	 */
	private void replaceFragment(Fragment newFragment) {
		FragmentTransaction transaction = fragmentManager.beginTransaction();
		if (!newFragment.isAdded()) {
			transaction.replace(R.id.content_layout, newFragment);
			transaction.commit();
		} else {
			transaction.show(newFragment);
		}
	}

	/**
	 * �ı����󿨵�ѡ��״̬
	 */
	private void clearStatus() {
		if (index == 1) {
			tab1Layout.setBackgroundColor(getResources().getColor(R.color.tab));
		} else if (index == 2) {
			tab2Layout.setBackgroundColor(getResources().getColor(R.color.tab));
		} else if (index == 3) {
			tab3Layout.setBackgroundColor(getResources().getColor(R.color.tab));
		}
	}

	@Override
	public void onClick(View v) {
		clearStatus();
		switch (v.getId()) {
		case R.id.tab1_layout:
			if (tab1Fragment == null) {
				tab1Fragment = new Tab1Fragment();
			}
			replaceFragment(tab1Fragment);
			tab1Layout.setBackgroundColor(getResources().getColor(
					R.color.tab_down));
			index = 1;
			break;
		case R.id.tab2_layout:
			if (tab2Fragment == null) {
				tab2Fragment = new Tab2Fragment();
			}
			replaceFragment(tab2Fragment);
			tab2Layout.setBackgroundColor(getResources().getColor(
					R.color.tab_down));
			index = 2;
			break;
		case R.id.tab3_layout:
			if (tab3Fragment == null) {
				tab3Fragment = new Tab3Fragment();
			}
			replaceFragment(tab3Fragment);
			tab3Layout.setBackgroundColor(getResources().getColor(
					R.color.tab_down));
			index = 3;
			break;
		}
	}

}
