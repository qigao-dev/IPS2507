package com.service;


import com.model.LogEntry;
import com.repository.LogRepository;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class LogService {

    private final LogRepository logRepository;

    public LogService(LogRepository logRepository) {
        this.logRepository = logRepository;
    }

    public List<LogEntry> searchByThreatName(String threatName) {
        return logRepository.searchByThreatName(threatName);
    }

    public List<LogEntry> searchByIp(String ip) {
        return logRepository.searchByIp(ip);
    }

    public List<LogEntry> searchByTimeRange(Date startTime, Date endTime) {
        return logRepository.searchByTimeRange(startTime, endTime);
    }

    public List<LogEntry> searchAll() {
        return logRepository.searchByTimeRange(
                new Date(0), // 从 1970 年开始
                new Date()  // 到现在
        );
    }
}
