package com.subhanmalik.loglens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LogParserTest {

    private static final String COMBINED =
            "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "
            + "\"GET /apache_pb.gif HTTP/1.0\" 200 2326 "
            + "\"http://www.example.com/start.html\" \"Mozilla/4.08 [en] (Win98; I ;Nav)\"";

    private static final String COMMON =
            "127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] \"GET /index.html HTTP/1.1\" 404 512";

    @Test
    void parsesCombinedLine() throws LogParseException {
        LogEntry e = LogParser.parseLine(COMBINED, 1);
        assertEquals("127.0.0.1", e.ip());
        assertEquals("GET", e.method());
        assertEquals("/apache_pb.gif", e.path());
        assertEquals("HTTP/1.0", e.protocol());
        assertEquals(200, e.status());
        assertEquals(2326, e.bytes());
        assertEquals("http://www.example.com/start.html", e.referer());
        assertTrue(e.userAgent().contains("Mozilla"));
        assertEquals(13, e.timestamp().getHour());
        assertEquals(2000, e.timestamp().getYear());
        assertNull(e.requestTimeSeconds());
    }

    @Test
    void parsesCommonLine() throws LogParseException {
        LogEntry e = LogParser.parseLine(COMMON, 1);
        assertEquals(404, e.status());
        assertEquals(512, e.bytes());
        assertNull(e.referer());
        assertNull(e.userAgent());
    }

    @Test
    void dashBytesBecomesMinusOne() throws LogParseException {
        LogEntry e = LogParser.parseLine(
                "10.0.0.1 - - [01/Jan/2026:00:00:01 +0000] \"HEAD /ping HTTP/1.1\" 304 -", 1);
        assertEquals(-1, e.bytes());
        assertTrue(e.hasNoBytes());
    }

    @Test
    void dashRefererAndAgentBecomeNull() throws LogParseException {
        LogEntry e = LogParser.parseLine(
                "10.0.0.1 - - [01/Jan/2026:00:00:01 +0000] \"GET /a HTTP/1.1\" 200 10 "
                + "\"-\" \"-\"", 1);
        assertNull(e.referer());
        assertNull(e.userAgent());
    }

    @Test
    void parsesTrailingRequestTime() throws LogParseException {
        LogEntry e = LogParser.parseLine(COMBINED + " 0.042", 1);
        assertEquals(0.042, e.requestTimeSeconds(), 1e-9);
    }

    @Test
    void parsesIpv6Address() throws LogParseException {
        LogEntry e = LogParser.parseLine(
                "2001:db8::1 - - [01/Jan/2026:00:00:01 +0000] "
                + "\"GET /v6 HTTP/1.1\" 200 100", 1);
        assertEquals("2001:db8::1", e.ip());
    }

    @Test
    void preservesQueryStringInPath() throws LogParseException {
        LogEntry e = LogParser.parseLine(
                "10.0.0.1 - - [01/Jan/2026:00:00:01 +0000] "
                + "\"GET /search?q=java&page=2 HTTP/1.1\" 200 100", 1);
        assertEquals("/search?q=java&page=2", e.path());
    }

    @Test
    void rejectsGarbageLine() {
        LogParseException ex = assertThrows(LogParseException.class,
                () -> LogParser.parseLine("this is not a log line", 7));
        assertEquals(7, ex.lineNumber());
        assertTrue(ex.getMessage().contains("line 7"));
    }

    @Test
    void rejectsBlankLine() {
        assertThrows(LogParseException.class, () -> LogParser.parseLine("   ", 3));
    }

    @Test
    void rejectsBadTimestamp() {
        assertThrows(LogParseException.class, () -> LogParser.parseLine(
                "10.0.0.1 - - [not-a-date] \"GET /a HTTP/1.1\" 200 10", 1));
    }

    @Test
    void rejectsMalformedRequestLine() {
        assertThrows(LogParseException.class, () -> LogParser.parseLine(
                "10.0.0.1 - - [01/Jan/2026:00:00:01 +0000] \"GET\" 200 10", 1));
    }

    @Test
    void forcedCommonFormatRejectsCombined() {
        assertThrows(LogParseException.class, () -> LogParser.parseLine(
                COMBINED, 1, LogParser.Format.COMMON));
    }

    @Test
    void statusClassAndErrorHelpers() throws LogParseException {
        LogEntry ok = LogParser.parseLine(COMMON, 1);
        assertEquals(4, ok.statusClass());
        assertTrue(ok.isError());
        LogEntry fine = LogParser.parseLine(COMBINED, 1);
        assertEquals(2, fine.statusClass());
    }
}
