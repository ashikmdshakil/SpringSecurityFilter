package com.getwell.customer.model;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@Component
@Document
@Scope(scopeName = "prototype")
public class User {
    //user basic information
    @Id
    private String id;
    private String name;
    private String email;
    private String mobileNumber;
    private String password;

    //vendor's rating by consumers
    private double rating;

    //User Profile Picture
    private String image;

    //user address
    private double[] geoLocation;
    private String address;

    //user ip and date info
    private String registrationIp;
    private LocalDateTime registrationDate;
    private String loginIp;
    private String lastLoginIp;

    //By defaults users are inactive
    private boolean active = false;
    //for branch request
    private boolean requested = false;

    //Reference vendor for branch
    private User referenceVendor;

    //User roles
    @DBRef(lazy = true)
    private List<Role> roles = new ArrayList<>();
}
