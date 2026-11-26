package com.subhanmalik.loglens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportAndMainTest {

    private static final String LOG =
            "203.0.113.1 - - [26/Nov/2026:10:00:00 +0500] \"GET /index.html HTTP/1.1\" 200 1024 "
            + "\"-\" \"Mozilla/5.0\" 0.120\n"
            + "203.0.113.2 - - [26/Nov/2026:10:01:00 +0500] \"GET /index.html HTTP/1.1\" 200 1024 "
            + "\"-\" \"Mozilla/5.0\" 0.080\n"
            + "203.0.113.3 - - [26/Nov/2026:10:02:00 +0500] \"GET /nope HTTP/1.1\" 404 512 "
            + "\"-\" \"Googlebot/2.1\" 0.900\n"
            + "203.0.113.3 - - [26/Nov/2026:11:00:00 +0500] \"POST /api/login HTTP/1.1\" 500 64 "
            + "\"-\" \"curl/8.0\" 1.250\n";

    private Path writeLog(Path dir) throws IOException {
        Path file = dir.resolve("access.log");
        Files.writeString(file, LOG);
        return file;
    }

    private String runCli(Path file, String... extra) {
        String[] args = new String[extra.length + 1];
        args[0] = file.toString();
        System.arraycopy(extra, 0, args, 1, extra.length);
        StringBuilder out = new StringBuilder();
        int code = Main.run(args, out::append, s -> {
        });
        assertEquals(0, code);
        return out.toString();
    }

    @Test
    void textReportCoversKeySections(@TempDir Path dir) throws IOException {
        String report = runCli(writeLog(dir));
        assertTrue(report.contains("Requests analysed: 4"));
        assertTrue(report.contains("200"));
        assertTrue(report.contains("Error rate:        50.00%"));
        assertTrue(report.contains("/index.html"));
        assertTrue(report.contains("Bot requests:      1"));
        assertTrue(report.contains("p95"));
        assertTrue(report.contains("Slowest requests"));
    }

    @Test
    void jsonReportIsWellFormed(@TempDir Path dir) throws IOException {
        String json = runCli(writeLog(dir), "--json");
        assertTrue(json.startsWith("{"));
        assertTrue(json.contains("\"requests\":4"));
        assertTrue(json.contains("\"statusCounts\":{\"200\":2,\"404\":1,\"500\":1}"));
        assertTrue(json.contains("\"topPaths\""));
        assertTrue(json.contains("\"requestTimeP50\":0.12"));
    }

    @Test
    void statusFilterNarrowsReport(@TempDir Path dir) throws IOException {
        String report = runCli(writeLog(dir), "--status", "404");
        assertTrue(report.contains("Requests analysed: 1"));
        assertTrue(report.contains("Filtered out:      3"));
    }

    @Test
    void sinceFilterNarrowsReport(@TempDir Path dir) throws IOException {
        String report = runCli(writeLog(dir), "--since", "2026-11-26T11:00:00+05:00");
        assertTrue(report.contains("Requests analysed: 1"));
    }

    @Test
    void topZeroOmitsTopLists(@TempDir Path dir) throws IOException {
        String report = runCli(writeLog(dir), "--top", "0");
        assertTrue(report.contains("Top paths (by requests)"));
        assertTrue(report.contains("(none)"));
    }

    @Test
    void strictModeFailsOnMalformedLine(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("bad.log");
        Files.writeString(file, LOG + "garbage line\n");
        StringBuilder err = new StringBuilder();
        int code = Main.run(new String[]{file.toString()}, s -> {
        }, err::append);
        assertEquals(2, code);
        assertTrue(err.toString().contains("line 5"));
    }

    @Test
    void tolerantModeSkipsMalformedLine(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("bad.log");
        Files.writeString(file, LOG + "garbage line\n");
        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        int code = Main.run(new String[]{file.toString(), "--tolerant"}, out::append, err::append);
        assertEquals(0, code);
        assertTrue(out.toString().contains("Requests analysed: 4"));
        assertTrue(out.toString().contains("Malformed lines:   1"));
    }

    @Test
    void usageErrorsReturnOne() {
        StringBuilder err = new StringBuilder();
        assertEquals(1, Main.run(new String[]{}, s -> {
        }, err::append));
        assertEquals(1, Main.run(new String[]{"--bogus", "x"}, s -> {
        }, err::append));
        assertEquals(1, Main.run(new String[]{"--top", "abc", "x"}, s -> {
        }, err::append));
        assertEquals(1, Main.run(new String[]{"--status", "99", "x"}, s -> {
        }, err::append));
        assertEquals(1, Main.run(new String[]{"--since", "not-a-date", "x"}, s -> {
        }, err::append));
    }

    @Test
    void helpReturnsZero() {
        StringBuilder out = new StringBuilder();
        assertEquals(0, Main.run(new String[]{"--help"}, out::append, s -> {
        }));
        assertTrue(out.toString().contains("Usage:"));
    }

    @Test
    void missingFileReturnsTwo() {
        StringBuilder err = new StringBuilder();
        assertEquals(2, Main.run(new String[]{"/no/such/file.log"}, s -> {
        }, err::append));
        assertTrue(err.toString().contains("cannot read file"));
    }

    @Test
    void jsonEscapesQuotesAndControlChars() {
        LogAnalyzer a = new LogAnalyzer();
        a.accept(new LogEntry("1.1.1.1",
                java.time.OffsetDateTime.parse("2026-11-26T10:00:00+05:00"),
                "GET", "/we\"ird\npath", "HTTP/1.1", 200, 10, null, null, null));
        String json = Report.json(a, 10, List.of());
        assertTrue(json.contains("/we\\\"ird\\npath"));
        String text = Report.text(a, 10, List.of());
        assertTrue(text.contains("/we\"ird"));
    }
}
