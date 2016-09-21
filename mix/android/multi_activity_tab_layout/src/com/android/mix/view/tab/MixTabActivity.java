package com.android.mix.view.tab;

import com.android.mix.R;

import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentTransaction;
import android.view.View;
import android.widget.ImageButton;

public class MixTabActivity extends FragmentActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_mixtab);

        initComponents();

    }
    
    
    View currentButton;
    
    
    protected static final String TAG = "MixTabActivity";
    
    
    private void initComponents() {
        
        ImageButton btn_contact = (ImageButton) findViewById(R.id.buttom_contact);
        ImageButton btn_ems = (ImageButton) findViewById(R.id.buttom_ems);
        ImageButton btn_fold= (ImageButton) findViewById(R.id.buttom_fold);
        ImageButton btn_setup = (ImageButton) findViewById(R.id.buttom_setup);

        btn_contact.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                FragmentManager fm = getSupportFragmentManager();
                FragmentTransaction ft = fm.beginTransaction();
                Fragment_One fragment_one = new Fragment_One();
                ft.replace(R.id.fl_content_mixtab, fragment_one, MixTabActivity.TAG);
                ft.commit();
                setButton(v);

            }
        });

        btn_ems.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                FragmentManager fm = getSupportFragmentManager();
                FragmentTransaction ft = fm.beginTransaction();
                Fragment_Two fragment_two = new Fragment_Two();
                ft.replace(R.id.fl_content_mixtab, fragment_two, MixTabActivity.TAG);
                ft.commit();
                setButton(v);

            }
        });


        btn_fold.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                FragmentManager fm = getSupportFragmentManager();
                FragmentTransaction ft = fm.beginTransaction();
                Fragment_Three fragment_three = new Fragment_Three();
                ft.replace(R.id.fl_content_mixtab, fragment_three, MixTabActivity.TAG);
                ft.commit();
                setButton(v);
            }
        });
        
        btn_setup.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                FragmentManager fm = getSupportFragmentManager();
                FragmentTransaction ft = fm.beginTransaction();
                Fragment_Four fragment_four = new Fragment_Four();
                ft.replace(R.id.fl_content_mixtab, fragment_four, MixTabActivity.TAG);
                ft.commit();
                setButton(v);
            }
        });

        /**
         * 榛樿绗竴涓寜閽偣鍑�
         */
        btn_contact.performClick();

    }

    /**
     * 璁剧疆鎸夐挳鐨勮儗鏅浘鐗�
     *
     * @param v
     */
    private void setButton(View v) {
        if (currentButton != null && currentButton.getId() != v.getId()) {
            currentButton.setEnabled(true);
        }
        v.setEnabled(false);
        currentButton = v;
    }
	
}
