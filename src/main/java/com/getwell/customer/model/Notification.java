package com.getwell.customer.model;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Data
@Component
@Document
@Scope(scopeName = "prototype")
public class Notification {
    @Id
    private String id;
    private String message;
    private String mobileNumber;
    private String role;
    private LocalDateTime time;
}
