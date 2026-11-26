package com.subhanmalik.loglens;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Apache/Nginx access-log lines.
 *
 * <p>Supported formats:
 * <ul>
 *   <li><b>Common</b> — {@code ip - - [date] "METHOD path proto" status bytes}</li>
 *   <li><b>Combined</b> — common plus {@code "referer" "user-agent"}, with an
 *       optional trailing request-time field in seconds (the Nginx
 *       {@code $request_time} value many setups append).</li>
 * </ul>
 *
 * <p>Design decisions:
 * <ul>
 *   <li>One compiled regex per format, with named groups — a hand-rolled
 *       char scanner would be faster but far harder to read, and log
 *       analysis is I/O-bound anyway.</li>
 *   <li>Parsing is <em>streaming</em>: {@link #parseFile} reads line by line
 *       and hands each entry to a consumer, so multi-gigabyte logs never
 *       sit in memory. Only the aggregated statistics are retained.</li>
 *   <li>Strict by default: the first malformed line aborts with a
 *       {@link LogParseException} naming the line number. Tolerant mode
 *       skips bad lines and reports them at the end instead.</li>
 * </ul>
 */
public final class LogParser {

    /** Log timestamp, e.g. {@code 10/Oct/2000:13:55:36 -0700}. */
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    // ip ident auth [date] "request" status bytes ["referer" "agent"] [req-time]
    private static final Pattern COMBINED = Pattern.compile(
            "^(?<ip>\\S+) \\S+ \\S+ \\[(?<time>[^\\]]+)] \"(?<request>[^\"]*)\" "
            + "(?<status>\\d{3}) (?<bytes>\\d+|-) "
            + "\"(?<referer>[^\"]*)\" \"(?<agent>[^\"]*)\""
            + "(?: (?<reqtime>\\d+(?:\\.\\d+)?))?$");

    private static final Pattern COMMON = Pattern.compile(
            "^(?<ip>\\S+) \\S+ \\S+ \\[(?<time>[^\\]]+)] \"(?<request>[^\"]*)\" "
            + "(?<status>\\d{3}) (?<bytes>\\d+|-)$");

    /** The two formats this parser understands. */
    public enum Format {
        COMMON, COMBINED, AUTO
    }

    private LogParser() {
    }

    /** Parses a single line. The format is detected from the line itself. */
    public static LogEntry parseLine(String line, int lineNumber) throws LogParseException {
        return parseLine(line, lineNumber, Format.AUTO);
    }

    /** Parses a single line as the given format ({@code AUTO} detects it). */
    public static LogEntry parseLine(String line, int lineNumber, Format format)
            throws LogParseException {
        if (line == null || line.isBlank()) {
            throw new LogParseException(lineNumber, line, "blank line");
        }
        Matcher m = null;
        Format used = format;
        if (format == Format.COMBINED || format == Format.AUTO) {
            m = COMBINED.matcher(line);
            if (m.matches()) {
                used = Format.COMBINED;
            } else if (format == Format.COMBINED) {
                throw new LogParseException(lineNumber, line, "does not match combined log format");
            }
        }
        if (m == null || !m.matches()) {
            m = COMMON.matcher(line);
            if (!m.matches()) {
                throw new LogParseException(lineNumber, line,
                        "does not match common or combined log format");
            }
            used = Format.COMMON;
        }
        return toEntry(m, used, lineNumber, line);
    }

    private static LogEntry toEntry(Matcher m, Format format, int lineNumber, String rawLine)
            throws LogParseException {
        OffsetDateTime timestamp;
        try {
            timestamp = OffsetDateTime.parse(m.group("time"), TIMESTAMP);
        } catch (DateTimeParseException e) {
            throw new LogParseException(lineNumber, rawLine,
                    "bad timestamp '" + m.group("time") + "'");
        }

        String request = m.group("request");
        String[] parts = request.split(" ", 3);
        if (parts.length < 2) {
            throw new LogParseException(lineNumber, rawLine,
                    "malformed request line '" + request + "'");
        }
        String method = parts[0];
        String path = parts[1];
        String protocol = parts.length == 3 ? parts[2] : null;

        int status = Integer.parseInt(m.group("status"));
        String bytesRaw = m.group("bytes");
        long bytes = "-".equals(bytesRaw) ? -1 : Long.parseLong(bytesRaw);

        String referer = null;
        String agent = null;
        Double requestTime = null;
        if (format == Format.COMBINED) {
            referer = "-".equals(m.group("referer")) ? null : m.group("referer");
            agent = "-".equals(m.group("agent")) ? null : m.group("agent");
            String rt = m.group("reqtime");
            if (rt != null) {
                requestTime = Double.parseDouble(rt);
            }
        }
        return new LogEntry(m.group("ip"), timestamp, method, path, protocol,
                status, bytes, referer, agent, requestTime);
    }

    /**
     * Streams a log file, handing each parsed entry to {@code consumer}.
     *
     * @param path     log file to read
     * @param format   format to expect ({@code AUTO} detects per line)
     * @param tolerant when true, malformed lines are collected and returned
     *                 instead of aborting; when false the first bad line
     *                 throws
     * @return the malformed lines seen (empty in strict mode, which throws)
     */
    public static List<LogParseException> parseFile(Path path, Format format,
            boolean tolerant, Consumer<LogEntry> consumer)
            throws IOException, LogParseException {
        List<LogParseException> errors = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                try {
                    consumer.accept(parseLine(line, lineNumber, format));
                } catch (LogParseException e) {
                    if (!tolerant) {
                        throw e;
                    }
                    errors.add(e);
                }
            }
        }
        return errors;
    }
}
