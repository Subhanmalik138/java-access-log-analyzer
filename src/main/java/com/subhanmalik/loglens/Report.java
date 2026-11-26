package com.subhanmalik.loglens;

import java.util.List;
import java.util.Map;

/**
 * Renders a {@link LogAnalyzer} snapshot as a human-readable text report
 * or as JSON (hand-rolled escaping — no dependency for one small object).
 */
public final class Report {

    private Report() {
    }

    public static String text(LogAnalyzer a, int top, List<LogParseException> errors) {
        StringBuilder sb = new StringBuilder();
        sb.append("Access log report\n");
        sb.append("=================\n");
        sb.append(String.format("Requests analysed: %,d%n", a.total()));
        if (a.filteredOut() > 0) {
            sb.append(String.format("Filtered out:      %,d%n", a.filteredOut()));
        }
        if (!errors.isEmpty()) {
            sb.append(String.format("Malformed lines:   %,d (skipped)%n", errors.size()));
        }
        sb.append(String.format("Bytes served:      %,d (avg %,.0f / request)%n",
                a.totalBytes(), a.averageBytes()));
        sb.append(String.format("Error rate:        %.2f%% (4xx + 5xx)%n", a.errorRate() * 100));
        sb.append(String.format("Bot requests:      %,d (%.2f%%)%n",
                a.botRequests(),
                a.total() == 0 ? 0 : 100.0 * a.botRequests() / a.total()));

        sb.append("\nStatus codes\n------------\n");
        if (a.statusCounts().isEmpty()) {
            sb.append("(none)\n");
        }
        a.statusCounts().forEach((code, count) ->
                sb.append(String.format("  %d  %,d%n", code, count)));

        sb.append("\nMethods\n-------\n");
        if (a.methodCounts().isEmpty()) {
            sb.append("(none)\n");
        }
        LogAnalyzer.topN(a.methodCounts(), Integer.MAX_VALUE)
                .forEach(e -> sb.append(String.format("  %-8s %,d%n", e.getKey(), e.getValue())));

        appendTop(sb, "Top paths (by requests)", a.topPaths(top));
        appendTop(sb, "Top paths (by bytes)", a.topPathsByBytes(top));
        appendTop(sb, "Top client IPs", a.topIps(top));
        if (a.botRequests() > 0) {
            appendTop(sb, "Top bots", a.topBots(top));
        }

        sb.append("\nRequests per hour\n-----------------\n");
        a.hourlyMap().forEach((hour, count) ->
                sb.append(String.format("  %02d:00  %,d%n", hour, count)));

        double p50 = a.requestTimePercentile(50);
        if (p50 >= 0) {
            sb.append("\nRequest time (seconds, from log)\n");
            sb.append("----------------------------------\n");
            sb.append(String.format("  p50  %.3f%n", p50));
            sb.append(String.format("  p95  %.3f%n", a.requestTimePercentile(95)));
            sb.append(String.format("  p99  %.3f%n", a.requestTimePercentile(99)));
            sb.append("\nSlowest requests\n----------------\n");
            for (LogEntry e : a.slowestRequests(top)) {
                sb.append(String.format("  %.3fs  %s %s%n",
                        e.requestTimeSeconds(), e.method(), e.path()));
            }
        }
        return sb.toString();
    }

    private static void appendTop(StringBuilder sb, String title,
            List<Map.Entry<String, Long>> entries) {
        sb.append("\n").append(title).append("\n");
        sb.append("-".repeat(title.length())).append("\n");
        if (entries.isEmpty()) {
            sb.append("(none)\n");
            return;
        }
        entries.forEach(e -> sb.append(String.format("  %,6d  %s%n", e.getValue(), e.getKey())));
    }

    public static String json(LogAnalyzer a, int top, List<LogParseException> errors) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        field(sb, "requests", a.total(), true);
        field(sb, "filteredOut", a.filteredOut(), false);
        field(sb, "malformedLines", errors.size(), false);
        field(sb, "totalBytes", a.totalBytes(), false);
        field(sb, "averageBytes", round(a.averageBytes(), 2), false);
        field(sb, "errorRate", round(a.errorRate(), 4), false);
        field(sb, "botRequests", a.botRequests(), false);
        sb.append(",\"statusCounts\":").append(longMap(a.statusCounts()));
        sb.append(",\"statusClassCounts\":").append(longMap(a.statusClassCounts()));
        sb.append(",\"methodCounts\":").append(stringLongMap(a.methodCounts()));
        sb.append(",\"topPaths\":").append(topList(a.topPaths(top)));
        sb.append(",\"topPathsByBytes\":").append(topList(a.topPathsByBytes(top)));
        sb.append(",\"topIps\":").append(topList(a.topIps(top)));
        sb.append(",\"topBots\":").append(topList(a.topBots(top)));
        sb.append(",\"hourly\":").append(longMap(a.hourlyMap()));
        double p50 = a.requestTimePercentile(50);
        if (p50 >= 0) {
            field(sb, "requestTimeP50", round(p50, 3), false);
            field(sb, "requestTimeP95", round(a.requestTimePercentile(95), 3), false);
            field(sb, "requestTimeP99", round(a.requestTimePercentile(99), 3), false);
            sb.append(",\"slowest\":[");
            boolean first = true;
            for (LogEntry e : a.slowestRequests(top)) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                sb.append("{\"seconds\":").append(e.requestTimeSeconds())
                        .append(",\"method\":").append(quote(e.method()))
                        .append(",\"path\":").append(quote(e.path()))
                        .append(",\"status\":").append(e.status()).append("}");
            }
            sb.append("]");
        }
        sb.append("}");
        return sb.toString();
    }

    private static double round(double value, int places) {
        double scale = Math.pow(10, places);
        return Math.round(value * scale) / scale;
    }

    private static void field(StringBuilder sb, String name, long value, boolean first) {
        if (!first) {
            sb.append(",");
        }
        sb.append(quote(name)).append(":").append(value);
    }

    private static void field(StringBuilder sb, String name, double value, boolean first) {
        if (!first) {
            sb.append(",");
        }
        sb.append(quote(name)).append(":").append(value);
    }

    private static String longMap(Map<?, Long> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<?, Long> e : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append(quote(String.valueOf(e.getKey()))).append(":").append(e.getValue());
        }
        return sb.append("}").toString();
    }

    private static String stringLongMap(Map<String, Long> map) {
        return longMap(map);
    }

    private static String topList(List<Map.Entry<String, Long>> entries) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Map.Entry<String, Long> e : entries) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("{\"key\":").append(quote(e.getKey()))
                    .append(",\"count\":").append(e.getValue()).append("}");
        }
        return sb.append("]").toString();
    }

    /** JSON string escaping: quotes, backslashes and control characters. */
    static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append("\"").toString();
    }
}
