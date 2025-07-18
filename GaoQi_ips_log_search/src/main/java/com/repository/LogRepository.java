package com.repository;

import com.model.LogEntry;
import org.elasticsearch.index.query.QueryBuilders;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.data.elasticsearch.core.query.NativeSearchQuery;
import org.springframework.data.elasticsearch.core.query.NativeSearchQueryBuilder;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Repository
public class LogRepository {

    private final ElasticsearchOperations elasticsearchOperations;

    public LogRepository(ElasticsearchOperations elasticsearchOperations) {
        this.elasticsearchOperations = elasticsearchOperations;
    }

    public List<LogEntry> searchByThreatName(String threatName) {
        NativeSearchQuery searchQuery = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.matchQuery("threatName", threatName))
                .build();

        SearchHits<LogEntry> searchHits = elasticsearchOperations.search(searchQuery, LogEntry.class);
        return searchHits.stream().map(SearchHit::getContent).collect(Collectors.toList());
    }

    public List<LogEntry> searchByIp(String ip) {
        NativeSearchQuery searchQuery = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.boolQuery()
                        .should(QueryBuilders.matchQuery("sourceIp", ip))
                        .should(QueryBuilders.matchQuery("destinationIp", ip)))
                .build();

        SearchHits<LogEntry> searchHits = elasticsearchOperations.search(searchQuery, LogEntry.class);
        return searchHits.stream().map(SearchHit::getContent).collect(Collectors.toList());
    }

    public List<LogEntry> searchByTimeRange(Date startTime, Date endTime) {
        NativeSearchQuery searchQuery = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.rangeQuery("timestamp")
                        .gte(startTime.getTime())
                        .lte(endTime.getTime()))
                .build();

        SearchHits<LogEntry> searchHits = elasticsearchOperations.search(searchQuery, LogEntry.class);
        return searchHits.stream().map(SearchHit::getContent).collect(Collectors.toList());
    }
}
