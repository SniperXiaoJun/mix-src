package com.android.mix.view.tab;

import com.android.mix.R;

import android.app.Activity;
import android.app.TabActivity;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.TabHost;
import android.widget.Toast;
import android.widget.TabHost.OnTabChangeListener;

/**
 * ʹ��TabWidget��TabHost��TabActivity4ʵ��
 * <p>
 * TabActivity��API13֮��fragment����ˣ����Բ�����ʹ��</>
 * 
 * @since 2015��1��13��
 * @author jacksen
 * 
 */
public class TabHostAndTabWidgetActivity extends TabActivity {

	private TabHost tabHost;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_tabhostandtabwidget);

		tabHost = getTabHost();

		tabHost.addTab(tabHost
				.newTabSpec("111")
				.setIndicator("", getResources().getDrawable(R.drawable.skin_tab_icon_contact_normal))
				.setContent(R.id.tab1));

		tabHost.addTab(tabHost
				.newTabSpec("222")
				.setIndicator("",
						getResources().getDrawable(R.drawable.skin_tab_icon_conversation_normal))
				.setContent(R.id.tab2));

		tabHost.addTab(tabHost.newTabSpec("333")
				.setIndicator("", getResources().getDrawable(R.drawable.skin_tab_icon_news_normal))
				.setContent(R.id.tab3));

		tabHost.setBackgroundColor(Color.argb(150, 22, 70, 150));
		tabHost.setCurrentTab(0);
		tabHost.setOnTabChangedListener(new OnTabChangeListener() {
			@Override
			public void onTabChanged(String tabId) {
				Toast.makeText(TabHostAndTabWidgetActivity.this, tabId, Toast.LENGTH_SHORT)
						.show();
			}
		});

	}

}
