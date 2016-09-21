package com.android.mix.view.tab;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;

import com.android.mix.R;

/**
 * ��һ��tab�����ʵ�ַ�ʽ-- ViewPager +��PageAdapater
 * 
 * @since 2015��1��5��
 * @author jacksen
 * 
 */
public class ViewPagerAndPageAdapterActivity extends Activity {

	private ViewPager viewPager;
	private ArrayList<View> list = new ArrayList<>();
	// �ײ���Ĳ���
	private LinearLayout pointLayout;
	// �ײ��ĵ�
	private ImageView[] dots;
	// ��ǰѡ�е�����
	private int currentIndex;
	//
	private boolean flag = true;
	//����int
	private AtomicInteger what = new AtomicInteger(0);

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_viewpagerandpageadapter);

		init();
		initDots();
		
		loopPlay();
	}

	private void init() {
		viewPager = (ViewPager) findViewById(R.id.first_vp);
		LayoutInflater inflater = LayoutInflater.from(this);
		View view1 = inflater.inflate(R.layout.first_layout1, null);
		View view2 = inflater.inflate(R.layout.first_layout2, null);
		View view3 = inflater.inflate(R.layout.first_layout3, null);
		list.add(view1);
		list.add(view2);
		list.add(view3);

		viewPager.setAdapter(pagerAdapter);
		viewPager.setOnPageChangeListener(new OnPageChangeListener() {
			@Override
			public void onPageSelected(int arg0) {
				setDots(arg0);
			}

			@Override
			public void onPageScrolled(int arg0, float arg1, int arg2) {
			}

			@Override
			public void onPageScrollStateChanged(int arg0) {
			}
		});
	}

	/**
	 * ��ʼ���ײ��ĵ�
	 */
	private void initDots() {
		pointLayout = (LinearLayout) findViewById(R.id.point_layout);
		dots = new ImageView[list.size()];
		for (int i = 0; i < list.size(); i++) {
			dots[i] = (ImageView) pointLayout.getChildAt(i);
		}
		currentIndex = 0;
		dots[currentIndex].setBackgroundResource(R.drawable.point_selected);
	}

	/**
	 * �����ʱ����ı���ͼ
	 */
	private void setDots(int position) {
		if (position < 0 || position > list.size() - 1
				|| currentIndex == position) {
			return;
		}
		dots[position].setBackgroundResource(R.drawable.point_selected);
		dots[currentIndex].setBackgroundResource(R.drawable.point_nomal);
		currentIndex = position;
	}

	private PagerAdapter pagerAdapter = new PagerAdapter() {
		@Override
		public boolean isViewFromObject(View arg0, Object arg1) {
			return arg0 == arg1;
		}

		@Override
		public int getCount() {
			return list.size();
		}

		@Override
		public Object instantiateItem(ViewGroup container, int position) {
			container.addView(list.get(position));
			return list.get(position);
		}

		@Override
		public void destroyItem(ViewGroup container, int position, Object object) {
			container.removeView(list.get(position));
		}

	};

	private final Handler viewHandler = new Handler() {
		@Override
		public void handleMessage(android.os.Message msg) {
			viewPager.setCurrentItem(msg.what);
			setDots(msg.what);
		};
	};

	/**
	 * ѭ������ͼƬ
	 */
	private void loopPlay() {
		/**
		 * �����߳�4����ͼƬ�ֲ�-�����ֲ�
		 */
		new Thread(new Runnable() {
			public void run() {
				while (true) {
					viewHandler.sendEmptyMessage(what.get());

					if (what.get() >= list.size() - 1) {
						// what.getAndAdd(-3);
						flag = false;
					}
					if (what.get() < 1) {
						flag = true;
					}
					if (flag) {
						what.incrementAndGet();
					} else {
						what.decrementAndGet();
					}
					try {
						Thread.sleep(3000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
		}).start();
	}

}
