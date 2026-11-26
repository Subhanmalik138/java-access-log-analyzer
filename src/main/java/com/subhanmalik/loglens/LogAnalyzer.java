package com.subhanmalik.loglens;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Aggregates {@link LogEntry} values into the statistics a report needs.
 *
 * <p>Everything is computed in a single pass with fixed-size maps plus two
 * bounded lists (request times and slowest requests), so memory stays flat
 * relative to the log size except for the distinct paths/IPs/user-agents —
 * the unavoidable cost of top-N reporting.
 *
 * <p>Filtering ({@code since}/{@code until}/status/method) happens at
 * {@link #accept} time, so filtered-out entries cost nothing downstream.
 */
public final class LogAnalyzer {

    /** Substrings that mark a user agent as a bot or crawler. */
    private static final List<String> BOT_MARKERS = List.of(
            "bot", "crawler", "spider", "slurp", "crawl", "scraper",
            "googlebot", "bingbot", "duckduckbot", "baiduspider",
            "yandexbot", "ahrefsbot", "semrushbot", "mj12bot", "petalbot",
            "facebookexternalhit", "twitterbot", "applebot", "gptbot");

    private final OffsetDateTime since;
    private final OffsetDateTime until;
    private final Set<Integer> statuses;
    private final Set<String> methods;

    private long total;
    private long filteredOut;
    private final Map<Integer, Long> statusCounts = new TreeMap<>();
    private final Map<Integer, Long> statusClassCounts = new TreeMap<>();
    private final Map<String, Long> methodCounts = new HashMap<>();
    private final Map<String, Long> pathCounts = new HashMap<>();
    private final Map<String, Long> pathBytes = new HashMap<>();
    private final Map<String, Long> ipCounts = new HashMap<>();
    private final Map<String, Long> botCounts = new HashMap<>();
    private final long[] hourly = new long[24];
    private long totalBytes;
    private long bytesKnown;
    private long botRequests;
    private final List<Double> requestTimes = new ArrayList<>();
    private final List<LogEntry> slowest = new ArrayList<>();

    public LogAnalyzer() {
        this(null, null, null, null);
    }

    public LogAnalyzer(OffsetDateTime since, OffsetDateTime until,
            Set<Integer> statuses, Set<String> methods) {
        this.since = since;
        this.until = until;
        this.statuses = statuses;
        this.methods = methods;
    }

    /** Feeds one entry into the aggregation, applying the filters. */
    public void accept(LogEntry e) {
        if (since != null && e.timestamp().isBefore(since)
                || until != null && e.timestamp().isAfter(until)
                || statuses != null && !statuses.contains(e.status())
                || methods != null && !methods.contains(e.method())) {
            filteredOut++;
            return;
        }
        total++;
        statusCounts.merge(e.status(), 1L, Long::sum);
        statusClassCounts.merge(e.statusClass(), 1L, Long::sum);
        methodCounts.merge(e.method(), 1L, Long::sum);
        pathCounts.merge(e.path(), 1L, Long::sum);
        ipCounts.merge(e.ip(), 1L, Long::sum);
        if (e.bytes() >= 0) {
            totalBytes += e.bytes();
            bytesKnown++;
            pathBytes.merge(e.path(), e.bytes(), Long::sum);
        }
        hourly[e.timestamp().getHour()]++;
        if (isBot(e.userAgent())) {
            botRequests++;
            botCounts.merge(botName(e.userAgent()), 1L, Long::sum);
        }
        if (e.requestTimeSeconds() != null) {
            requestTimes.add(e.requestTimeSeconds());
            slowest.add(e);
        }
    }

    private static boolean isBot(String userAgent) {
        if (userAgent == null) {
            return false;
        }
        String lower = userAgent.toLowerCase();
        return BOT_MARKERS.stream().anyMatch(lower::contains);
    }

    /** Best-effort bot family name, e.g. "Googlebot" from its user agent. */
    private static String botName(String userAgent) {
        String lower = userAgent.toLowerCase();
        for (String marker : List.of("googlebot", "bingbot", "duckduckbot",
                "baiduspider", "yandexbot", "ahrefsbot", "semrushbot",
                "mj12bot", "petalbot", "facebookexternalhit", "twitterbot",
                "applebot", "gptbot")) {
            if (lower.contains(marker)) {
                return marker;
            }
        }
        return "other-bot";
    }

    public long total() {
        return total;
    }

    public long filteredOut() {
        return filteredOut;
    }

    public Map<Integer, Long> statusCounts() {
        return Collections.unmodifiableMap(statusCounts);
    }

    public Map<Integer, Long> statusClassCounts() {
        return Collections.unmodifiableMap(statusClassCounts);
    }

    public Map<String, Long> methodCounts() {
        return Collections.unmodifiableMap(methodCounts);
    }

    public long totalBytes() {
        return totalBytes;
    }

    /** Mean response size over entries that reported a byte count. */
    public double averageBytes() {
        return bytesKnown == 0 ? 0 : (double) totalBytes / bytesKnown;
    }

    /** Share of requests that were 4xx or 5xx, in [0, 1]. */
    public double errorRate() {
        if (total == 0) {
            return 0;
        }
        long errors = statusClassCounts.getOrDefault(4, 0L)
                + statusClassCounts.getOrDefault(5, 0L);
        return (double) errors / total;
    }

    public long botRequests() {
        return botRequests;
    }

    /** Requests per hour of day (index = hour, 0-23). */
    public long[] hourly() {
        return hourly.clone();
    }

    /** Top N entries of a count map, highest first, ties broken by key. */
    public static List<Map.Entry<String, Long>> topN(Map<String, Long> counts, int n) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(Math.max(0, n))
                .toList();
    }

    public List<Map.Entry<String, Long>> topPaths(int n) {
        return topN(pathCounts, n);
    }

    public List<Map.Entry<String, Long>> topIps(int n) {
        return topN(ipCounts, n);
    }

    public List<Map.Entry<String, Long>> topBots(int n) {
        return topN(botCounts, n);
    }

    /** Paths ranked by total bytes served, highest first. */
    public List<Map.Entry<String, Long>> topPathsByBytes(int n) {
        return topN(pathBytes, n);
    }

    /** Nearest-rank percentile of recorded request times, or -1 if none. */
    public double requestTimePercentile(double percentile) {
        if (requestTimes.isEmpty()) {
            return -1;
        }
        List<Double> sorted = new ArrayList<>(requestTimes);
        Collections.sort(sorted);
        int rank = (int) Math.ceil(percentile / 100.0 * sorted.size());
        return sorted.get(Math.min(Math.max(rank, 1), sorted.size()) - 1);
    }

    /** Slowest requests first (only entries that carried a request time). */
    public List<LogEntry> slowestRequests(int n) {
        return slowest.stream()
                .sorted(Comparator.comparingDouble(LogEntry::requestTimeSeconds).reversed())
                .limit(Math.max(0, n))
                .toList();
    }

    /** Ordered per-hour counts for charting, as hour → count. */
    public Map<Integer, Long> hourlyMap() {
        Map<Integer, Long> out = new LinkedHashMap<>();
        for (int h = 0; h < 24; h++) {
            out.put(h, hourly[h]);
        }
        return out;
    }
}
