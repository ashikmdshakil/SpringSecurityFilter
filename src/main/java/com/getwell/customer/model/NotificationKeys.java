package com.getwell.customer.model;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;

@Data
@Component
@Document
@Scope(scopeName = "prototype")
public class NotificationKeys {
    @Id
    private String id;
    private String userMobileNumber;
    private String roleName;
    private String notificationKey;
}
