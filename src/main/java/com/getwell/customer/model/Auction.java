package com.getwell.customer.model;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.data.annotation.Id;
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
public class Auction {
    @Id
    private String id;
    private String comment;
    private List<String> files = new ArrayList<>();

    //Auction locationls
    private double[] geoLocation;
    private String address;

    //Auction duration
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private LocalDateTime orderEndTime;

    //Owner of the auction
    private User owner;

    //Auction status whether complete or not
    private String status;

    //Vendors who can perticipate
    @DBRef
    private List<User> vendors = new ArrayList<>();
    //Vendors ids who have made bid
    private List<String> bidingVendorsId = new ArrayList<>();

}
