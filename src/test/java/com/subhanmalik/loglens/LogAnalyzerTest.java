package com.subhanmalik.loglens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class LogAnalyzerTest {

    private static LogEntry entry(String ip, String method, String path, int status,
            long bytes, String agent, Double reqTime, int hour) {
        return new LogEntry(ip,
                OffsetDateTime.parse("2026-11-26T" + String.format("%02d", hour)
                        + ":00:00+05:00"),
                method, path, "HTTP/1.1", status, bytes, null, agent, reqTime);
    }

    private static LogEntry entry(String ip, String method, String path, int status,
            long bytes) {
        return entry(ip, method, path, status, bytes, "Mozilla/5.0", null, 10);
    }

    @Test
    void countsStatusesAndClasses() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(entry("1.1.1.1", "GET", "/", 200, 100));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 100));
        a.accept(entry("1.1.1.2", "GET", "/missing", 404, 50));
        a.accept(entry("1.1.1.2", "POST", "/api", 500, 0));
        assertEquals(4, a.total());
        assertEquals(Map.of(200, 2L, 404, 1L, 500, 1L), a.statusCounts());
        assertEquals(Map.of(2, 2L, 4, 1L, 5, 1L), a.statusClassCounts());
        assertEquals(0.5, a.errorRate(), 1e-9);
    }

    @Test
    void totalsBytesAndAverage() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(entry("1.1.1.1", "GET", "/", 200, 100));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 300));
        a.accept(entry("1.1.1.1", "GET", "/", 304, -1)); // '-' in the log: excluded
        assertEquals(400, a.totalBytes());
        assertEquals(200.0, a.averageBytes(), 1e-9);
    }

    @Test
    void topPathsOrderedByCountThenKey() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(entry("1.1.1.1", "GET", "/b", 200, 10));
        a.accept(entry("1.1.1.1", "GET", "/a", 200, 10));
        a.accept(entry("1.1.1.1", "GET", "/b", 200, 10));
        List<Map.Entry<String, Long>> top = a.topPaths(2);
        assertEquals("/b", top.get(0).getKey());
        assertEquals(2L, top.get(0).getValue());
        assertEquals("/a", top.get(1).getKey());
    }

    @Test
    void topPathsByBytesUsesTotalsNotCounts() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(entry("1.1.1.1", "GET", "/small", 200, 10));
        a.accept(entry("1.1.1.1", "GET", "/small", 200, 10));
        a.accept(entry("1.1.1.1", "GET", "/big.bin", 200, 5000));
        assertEquals("/big.bin", a.topPathsByBytes(1).get(0).getKey());
    }

    @Test
    void detectsBotsAndGroupsFamilies() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10,
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                null, 10));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10,
                "Mozilla/5.0 (compatible; bingbot/2.0)", null, 10));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10,
                "SomeRandomCrawler/1.0", null, 10));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10, "Mozilla/5.0", null, 10));
        assertEquals(3, a.botRequests());
        assertEquals(3, a.topBots(10).size());
        // all counts are 1, so ties break alphabetically by bot family name
        assertEquals("bingbot", a.topBots(10).get(0).getKey());
        assertEquals("googlebot", a.topBots(10).get(1).getKey());
        assertEquals("other-bot", a.topBots(10).get(2).getKey());
    }

    @Test
    void hourlyHistogramBucketsByHour() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10, "Mozilla/5.0", null, 0));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10, "Mozilla/5.0", null, 0));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10, "Mozilla/5.0", null, 23));
        assertEquals(2, a.hourly()[0]);
        assertEquals(1, a.hourly()[23]);
        assertEquals(0, a.hourly()[12]);
    }

    @Test
    void requestTimePercentiles() {
        LogAnalyzer a = new LogAnalyzer();
        for (double t : new double[]{0.1, 0.2, 0.3, 0.4, 0.5}) {
            a.accept(entry("1.1.1.1", "GET", "/", 200, 10, "Mozilla/5.0", t, 10));
        }
        assertEquals(0.3, a.requestTimePercentile(50), 1e-9);
        assertEquals(0.5, a.requestTimePercentile(95), 1e-9);
        assertEquals(0.5, a.requestTimePercentile(99), 1e-9);
        assertEquals(0.5, a.slowestRequests(1).get(0).requestTimeSeconds(), 1e-9);
    }

    @Test
    void noRequestTimesMeansNoPercentile() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10));
        assertEquals(-1, a.requestTimePercentile(50), 1e-9);
        assertTrue(a.slowestRequests(5).isEmpty());
    }

    @Test
    void filtersByStatusMethodAndTime() {
        OffsetDateTime since = OffsetDateTime.parse("2026-11-26T10:00:00+05:00");
        LogAnalyzer a = new LogAnalyzer(since, null, Set.of(200), Set.of("GET"));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10, "Mozilla/5.0", null, 10));
        a.accept(entry("1.1.1.1", "GET", "/", 404, 10, "Mozilla/5.0", null, 10));
        a.accept(entry("1.1.1.1", "POST", "/", 200, 10, "Mozilla/5.0", null, 10));
        a.accept(entry("1.1.1.1", "GET", "/", 200, 10, "Mozilla/5.0", null, 9));
        assertEquals(1, a.total());
        assertEquals(3, a.filteredOut());
    }

    @Test
    void emptyAnalyzerReportsZeroes() {
        LogAnalyzer a = new LogAnalyzer();
        assertEquals(0, a.total());
        assertEquals(0.0, a.errorRate(), 1e-9);
        assertEquals(0.0, a.averageBytes(), 1e-9);
        assertTrue(a.topPaths(5).isEmpty());
    }
}
