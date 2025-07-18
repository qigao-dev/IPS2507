package com.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.DateFormat;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

import java.util.Date;

@Data
@Document(indexName = "#{@environment.getProperty('app.es.index')}")
public class LogEntry {
    @Id
    private String eventId;

    @Field(type = FieldType.Date, format = DateFormat.date_time)
    private Date timestamp;

    @Field(type = FieldType.Keyword)
    private String sourceIp;

    @Field(type = FieldType.Integer)
    private Integer sourcePort;

    @Field(type = FieldType.Keyword)
    private String destinationIp;

    @Field(type = FieldType.Integer)
    private Integer destinationPort;

    @Field(type = FieldType.Keyword)
    private String protocol;

    @Field(type = FieldType.Keyword)
    private String threatCategory;

    @Field(type = FieldType.Keyword)
    private String threatName;

    @Field(type = FieldType.Keyword)
    private String threatLevel;

    @Field(type = FieldType.Text)
    private String details;
}