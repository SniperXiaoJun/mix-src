package com.android.mix.view.tab;

import java.util.ArrayList;
import java.util.List;

import com.android.mix.R;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.PagerTabStrip;
import android.support.v4.view.PagerTitleStrip;
import android.support.v4.view.ViewPager;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.ImageSpan;
import android.text.style.RelativeSizeSpan;
import android.view.LayoutInflater;
import android.view.View;

/**
 * ViewPager + PagerTitleStrip
 * 
 * @author jacksen
 * 
 */
public class ViewPagerAndPagerTitleStripActivity extends Activity {

	// viewpager
	private ViewPager viewPager;
	// viewpager�ı���
	private PagerTitleStrip titleStrip;
	// viewpager��ָʾ��
	private PagerTabStrip tabStrip;
	// view����
	private List<View> viewList;
	// ���⼯��
	private List<String> titleList;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_viewpagerandpagertitlestrip);

		init();
	}

	/**
	 * 
	 */
	private void init() {
		viewList = new ArrayList<>();
		LayoutInflater inflater = getLayoutInflater();
		View view = inflater.inflate(R.layout.first_layout1, null);
		viewList.add(view);
		view = inflater.inflate(R.layout.first_layout2, null);
		viewList.add(view);
		view = inflater.inflate(R.layout.first_layout3, null);
		viewList.add(view);

		//
		titleList = new ArrayList<>();
		titleList.add("Tab页1");
		titleList.add("Tab页2");
		titleList.add("Tab页3");

		initViewPager();
	}

	private void initViewPager() {
		viewPager = (ViewPager) findViewById(R.id.fifth_vp);
		viewPager.setAdapter(pagerAdapter);

		// �޸�ָʾ�����ɫ
		tabStrip = (PagerTabStrip) findViewById(R.id.fifth_strip);
		tabStrip.setTabIndicatorColor(Color.RED);
	}

	/**
	 * ������
	 */
	PagerAdapter pagerAdapter = new PagerAdapter() {

		/**
		 * �ٷ�������ôд
		 */
		@Override
		public boolean isViewFromObject(View arg0, Object arg1) {
			return arg0 == arg1;
		}

		@Override
		public int getCount() {
			return viewList.size();
		}

		/**
		 * ʵ��item
		 */
		@Override
		public Object instantiateItem(android.view.ViewGroup container,
				int position) {
			container.addView(viewList.get(position));
			return viewList.get(position);
		}

		/**
		 * ���item
		 */
		@Override
		public void destroyItem(android.view.ViewGroup container, int position,
				Object object) {
			container.removeView(viewList.get(position));
		}

		// ��д�˷���������ʾ����
		@Override
		public CharSequence getPageTitle(int position) {
			return titleList.get(position);
		}
	};
}
