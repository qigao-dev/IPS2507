package com.controller;


import com.model.LogEntry;
import com.service.LogService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Date;
import java.util.List;

@Controller
public class LogController {

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("logs", logService.searchAll());
        return "index";
    }

    @GetMapping("/search")
    public String search(
            @RequestParam(required = false) String threatName,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Date startTime,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Date endTime,
            Model model) {

        List<LogEntry> logs;

        if (threatName != null && !threatName.isEmpty()) {
            logs = logService.searchByThreatName(threatName);
        } else if (ip != null && !ip.isEmpty()) {
            logs = logService.searchByIp(ip);
        } else if (startTime != null && endTime != null) {
            logs = logService.searchByTimeRange(startTime, endTime);
        } else {
            logs = logService.searchAll();
        }

        model.addAttribute("logs", logs);
        return "index";
    }
}
