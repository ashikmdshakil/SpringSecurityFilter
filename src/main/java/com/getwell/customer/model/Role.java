package com.getwell.customer.model;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
@Document
@Scope(scopeName = "prototype")
public class Role {
    @Id
    private int id;
    private String name;
    //permissions for a role
    @DBRef
    private List<Permission> permissions;

}

