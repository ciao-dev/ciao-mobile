package com.isthatfreeproxysafe.ciao;

import java.util.Locale;

/**
 * Created by b.ran on 2/08/17.
 */

public class ProxyServerCountryInfo {

    private String countryCode;
    private String countryName;
    private int numAny; // Technically numAny = numAnonymous+numElite+numTransparent but we'll seee
    private int numAnonymous;
    private int numElite;
    private int numTransparent;

    public ProxyServerCountryInfo(String cc, int any, int ano, int elite, int trans) {
        this.countryCode = cc;
        this.numAny = any;
        this.numAnonymous = ano;
        this.numElite = elite;
        this.numTransparent = trans;
        this.countryName = (new Locale("", countryCode)).getDisplayCountry();
    }

    public String toString() {
        return "[Code: "+countryCode+" Name: "+countryName+", NumAny: "+numAny+
                ", NumAnonymous: "+numAnonymous+", NumElite: "+numElite
                +", NumTransparent: "+numTransparent+"]";
    }

    public int getNumAnonymous() {
        return numAnonymous;
    }

    public int getNumAny() {
        return numAny;
    }

    public int getNumElite() {
        return numElite;
    }

    public int getNumTransparent() {
        return numTransparent;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public String getCountryName() {
        return countryName;
    }
}
