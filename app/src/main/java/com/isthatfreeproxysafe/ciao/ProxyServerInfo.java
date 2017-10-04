package com.isthatfreeproxysafe.ciao;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Created by b.ran on 2/08/17.
 */


public class ProxyServerInfo implements Parcelable {
    public String addr;
    public int port;
    public boolean httpsProxy = false;
    public boolean masked = false;

    public ProxyServerInfo() {
        addr = null;
        port = 0;
    }

    public ProxyServerInfo(String addr, int port, boolean httpsProxy, boolean masked) {
        this.addr = addr;
        this.port = port;
        this.httpsProxy = httpsProxy;
        this.masked = masked;
    }

    public ProxyServerInfo(String addr, int port, boolean httpsProxy) {
        this.addr = addr;
        this.port = port;
        this.httpsProxy = httpsProxy;
    }

    public ProxyServerInfo(ProxyServerInfo other) {
        this.addr = other.addr;
        this.port = other.port;
        this.httpsProxy = other.httpsProxy;
    }

    public String toString() {return (httpsProxy ? "HTTPs Proxy: " : "HTTP Proxy: ")+addr+":"+port; }

    public Allowed toAllowed() {
        return new Allowed(addr, port, true, masked);
    }

    protected ProxyServerInfo(Parcel in) {
        addr = in.readString();
        port = in.readInt();
        httpsProxy = in.readByte() != 0x00;
        masked = in.readByte() != 0x00;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(addr);
        dest.writeInt(port);
        dest.writeByte((byte) (httpsProxy ? 0x01 : 0x00));
        dest.writeByte((byte) (masked ? 0x01 : 0x00));
    }

    @SuppressWarnings("unused")
    public static final Parcelable.Creator<ProxyServerInfo> CREATOR = new Parcelable.Creator<ProxyServerInfo>() {
        @Override
        public ProxyServerInfo createFromParcel(Parcel in) {
            return new ProxyServerInfo(in);
        }

        @Override
        public ProxyServerInfo[] newArray(int size) {
            return new ProxyServerInfo[size];
        }
    };
}
