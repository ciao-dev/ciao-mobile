package com.isthatfreeproxysafe.ciao;

import android.os.AsyncTask;
import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

/**
 * Created by b.ran on 4/09/17.
 */

public class StatisticsReportTask extends AsyncTask<String, Void, Void> {

    private static final String TAG = StatisticsReportTask.class.getSimpleName();
    private String serverName;
    private String path;

    public StatisticsReportTask(String serverName, String path) {
        this.serverName = serverName;
        this.path = path;
    }

    @Override
    protected Void doInBackground(String... stats) {

        try {
            Log.i(TAG, "post at "+serverName + path);
            URL url = new URL(serverName + path);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setReadTimeout(ActivityMain.URL_FETCH_TIMEOUT);
            conn.setConnectTimeout(ActivityMain.URL_FETCH_TIMEOUT);
            conn.setRequestMethod("POST");
            conn.setDoInput(true);
            conn.setDoOutput(true);

            OutputStream out = new BufferedOutputStream(conn.getOutputStream());
            BufferedWriter writer = new BufferedWriter (new OutputStreamWriter(out, "UTF-8"));

            writer.write(stats[0]);
            writer.flush();
            writer.close();
            out.close();

            conn.connect();

            int resCode = conn.getResponseCode();

            if(resCode != HttpsURLConnection.HTTP_OK)
                Log.e(TAG, "POST response: "+resCode+" : "+conn.getResponseMessage());

        } catch(Exception e) {
            e.printStackTrace();
            Log.e(TAG, "post failed");
        }
        return null;
    }
}
