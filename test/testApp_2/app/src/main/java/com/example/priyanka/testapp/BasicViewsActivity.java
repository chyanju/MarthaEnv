package com.example.priyanka.testapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.View;
import android.widget.EditText;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

public class BasicViewsActivity extends Activity {

	public static final String EXTRA_MESSAGE = "com.example.priyanka.testapp..MESSAGE";
	public String message = "";
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_basic_views);
	}

	public void goToMain(View view){
		Intent intent = new Intent();
		intent.setClass(this, MainActivity.class);
		startActivity(intent);
	}

	public void setMessage(View view){
		message = "Here";
	}
	public void goToDisplay(View view){

		if (message.equals("Here")) {
			URL url = null;
			try {
				url = new URL("http://www.mysite.se/index.asp?data=99");
			} catch (MalformedURLException e) {
				e.printStackTrace();
			}
			HttpURLConnection urlConnection = null;
			try {
				urlConnection = (HttpURLConnection) url.openConnection();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		Intent intent = new Intent();
		intent.setClass(this, DisplayMessageActivity.class);
		EditText editText = (EditText) findViewById(R.id.editText1);
		String message = editText.getText().toString();
		if (message == "")
			message = "Hello World";
		intent.putExtra(EXTRA_MESSAGE, message);
		startActivity(intent);

	}
}
