package com.getwell.customer.model;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Component
@Document
@Scope(scopeName = "prototype")
public class Biding {
    @Id
    private String id;
    private double totalPrice;
    private String comment;
    private String bidingStatus;
    private String paymentStatus;
    //The date when user turns a bid into order
    private LocalDateTime orderDate;

    //The Auction it belongs
    private Auction auction;

    //The vendor who bids
    private User vendor;

    //The owner of the auction
    private User owner;

    //Prescribed drugs
    private List<PrescribedDrug> drugs;
    private int totalDrugs;

}
