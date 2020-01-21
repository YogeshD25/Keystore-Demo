package com.example.sqlcipherexample;

import java.io.Serializable;

class Employee implements Serializable {
    public String name = "";
    public String ssn = "";

    public Employee(String name, String ssn) {
        this.name = name;
        this.ssn = ssn;
    }

}