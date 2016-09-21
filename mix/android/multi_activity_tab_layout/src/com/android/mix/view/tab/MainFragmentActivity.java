package com.android.mix.view.tab;

import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentTransaction;
import android.view.View;
import android.widget.ImageButton;
import com.android.mix.R;



public class MainFragmentActivity extends FragmentActivity {
    protected static final String TAG = "MainActivity";
    private View currentButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fragment);

        initComponents();

    }

    private void initComponents() {
        ImageButton btn_one = (ImageButton) findViewById(R.id.buttom_one);
        ImageButton btn_two = (ImageButton) findViewById(R.id.buttom_two);
        ImageButton btn_three = (ImageButton) findViewById(R.id.buttom_three);

        btn_one.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                FragmentManager fm = getSupportFragmentManager();
                FragmentTransaction ft = fm.beginTransaction();
                Fragment_One fragment_one = new Fragment_One();
                ft.replace(R.id.fl_content, fragment_one, MainFragmentActivity.TAG);
                ft.commit();
                setButton(v);

            }
        });

        btn_two.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                FragmentManager fm = getSupportFragmentManager();
                FragmentTransaction ft = fm.beginTransaction();
                Fragment_Two fragment_two = new Fragment_Two();
                ft.replace(R.id.fl_content, fragment_two, MainFragmentActivity.TAG);
                ft.commit();
                setButton(v);

            }
        });


        btn_three.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                FragmentManager fm = getSupportFragmentManager();
                FragmentTransaction ft = fm.beginTransaction();
                Fragment_Three fragment_three = new Fragment_Three();
                ft.replace(R.id.fl_content, fragment_three, MainFragmentActivity.TAG);
                ft.commit();
                setButton(v);
            }
        });

        /**
         * 榛樿绗竴涓寜閽偣鍑�
         */
        btn_one.performClick();

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
