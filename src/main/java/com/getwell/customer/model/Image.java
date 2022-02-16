package com.getwell.customer.model;

import lombok.Data;
import org.bson.types.Binary;
import org.springframework.context.annotation.Scope;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;

@Data
@Component
@Document
@Scope(scopeName = "prototype")
public class Image {
    @Id
    private String id;
    private String title;
    private Binary image;
}
