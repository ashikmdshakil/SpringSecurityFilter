package com.getwell.customer.model;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;

@Data
@Component
@Document
@Scope(scopeName = "prototype")
public class MedicineDump {
    private String id;
    private String medicineName;
    private String quantity;
    private String chemicalName;
    private String companyName;
    private String unitPrice;
}
