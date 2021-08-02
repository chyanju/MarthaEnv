package com.example.priyanka.testapp;

import android.content.ComponentName;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.EditText;
import android.widget.TextView;
public class MainActivity extends AppCompatActivity {

    public static final String EXTRA_MESSAGE = "com.example.priyanka.testapp..MESSAGE";
    private TextView mTextView;

    // The EditText where the user types the message.
    private EditText mEditText;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    /** Called when the user taps the Send button */
    public void showDisplay(View view) {
        Intent intent;
        intent = new Intent(this, DisplayMessageActivity.class);
        String message = "Welcome to the display";
        intent.putExtra(EXTRA_MESSAGE, message);
        startActivity(intent);
    }

    public void showBasicView(View view){
        Intent intent = new Intent();
        intent.setClass(this, BasicViewsActivity.class);
        startActivity(intent);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
        // This is our one standard application action -- inserting a
        // new note into the list.
        menu.add(0, 1, 1, R.string.basic_view)
                .setShortcut('3', 'a');
        menu.add(0, 0, 0, R.string.click_handler)
                .setShortcut('8', 'i');
        return true;

    }
    public boolean onOptionsItemSelected(MenuItem item) {
        Intent intent;
        switch (item.getItemId()) {
            case 0:
                intent = new Intent();
                intent.setClass(this, BasicClickHandlersActivity.class);
                startActivity(intent);
                return true;

            case 1:
                intent = new Intent();
                intent.setClass(this, BasicViewsActivity.class);
                startActivity(intent);
                return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
