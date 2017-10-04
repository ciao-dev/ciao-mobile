package com.isthatfreeproxysafe.ciao;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ResourceRecord {
    public long Time;
    public String QName;
    public String AName;
    public String Resource;
    public int TTL;

    private static DateFormat formatter = SimpleDateFormat.getDateTimeInstance();

    public ResourceRecord() {
    }

    @Override
    public String toString() {
        return formatter.format(new Date(Time).getTime()) +
                " Q " + QName +
                " A " + AName +
                " R " + Resource +
                " TTL " + TTL +
                " " + formatter.format(new Date(Time + TTL * 1000L).getTime());
    }

    public ResourceRecord(String s) throws ParseException{

        String[] parts = s.split(" Q ");
        this.Time = formatter.parse(parts[0]).getTime();
        parts = parts[1].split(" A ");
        this.QName = parts[0];
        parts = parts[1].split(" R ");
        this.AName = parts[0];
        parts = parts[1].split(" TTL ");
        this.Resource = parts[0];
        parts = parts[1].split(" ");
        this.TTL = Integer.valueOf(parts[0]);
    }
}
