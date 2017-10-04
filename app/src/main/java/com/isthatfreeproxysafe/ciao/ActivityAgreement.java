package com.isthatfreeproxysafe.ciao;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.preference.PreferenceManager;
import android.text.SpannableString;
import android.text.method.LinkMovementMethod;
import android.text.util.Linkify;
import android.widget.TextView;

/**
 * Created by b.ran on 2/10/17.
 */
public class ActivityAgreement {

    private String AGREEMENT_PREFIX = "agreement_";
    private Activity mActivity;

    public ActivityAgreement(Activity context) {
        mActivity = context;
    }

    private PackageInfo getPackageInfo() {
        PackageInfo pi = null;
        try {
            pi = mActivity.getPackageManager().getPackageInfo(mActivity.getPackageName(), PackageManager.GET_ACTIVITIES);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return pi;
    }

    public void show() {
        PackageInfo versionInfo = getPackageInfo();

        final String agreeKey = AGREEMENT_PREFIX + versionInfo.versionCode;
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(mActivity);
        boolean hasBeenShown = prefs.getBoolean(agreeKey, false);
        if(!hasBeenShown){
            String msg = mActivity.getString(R.string.agreement);

            String updateMessage = mActivity.getString(R.string.updates);
            if(!updateMessage.isEmpty()) {
                msg += "\n\n" + updateMessage;
            }
            final TextView message = new TextView(mActivity);
            final SpannableString s = new SpannableString(msg);
            Linkify.addLinks(s, Linkify.WEB_URLS);
            message.setText(s);
            message.setMovementMethod(LinkMovementMethod.getInstance());

            String title = mActivity.getString(R.string.app_name) + " v" + versionInfo.versionName;

            AlertDialog.Builder builder = new AlertDialog.Builder(mActivity)
                    .setTitle(title)
                    .setView(message)
                    .setPositiveButton(android.R.string.ok, new Dialog.OnClickListener() {

                        @Override
                        public void onClick(DialogInterface dialogInterface, int i) {
                            // Mark this version as read.
                            SharedPreferences.Editor editor = prefs.edit();
                            editor.putBoolean(agreeKey, true);
                            editor.commit();
                            dialogInterface.dismiss();
                        }
                    })
                    .setNegativeButton(android.R.string.cancel, new Dialog.OnClickListener() {

                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            mActivity.finish();
                        }

                    })
                    .setCancelable(false);
            AlertDialog d = builder.create();
            d.show();
        }
    }

}