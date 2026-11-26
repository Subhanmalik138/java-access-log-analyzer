package com.subhanmalik.loglens;

import java.time.OffsetDateTime;

/**
 * One parsed access-log line.
 *
 * <p>Models the Apache/Nginx <em>combined</em> log format. Fields that a
 * format does not carry are {@code null} (referer, user agent, request time)
 * or {@code -1} (bytes, when the log records {@code -}). The request line is
 * split into method, path and protocol at parse time so analysis never has
 * to re-split strings.
 */
public record LogEntry(
        String ip,
        OffsetDateTime timestamp,
        String method,
        String path,
        String protocol,
        int status,
        long bytes,
        String referer,
        String userAgent,
        Double requestTimeSeconds) {

    /** HTTP status class, e.g. {@code 2} for any 2xx status. */
    public int statusClass() {
        return status / 100;
    }

    /** True when the response was a client or server error (4xx or 5xx). */
    public boolean isError() {
        return status >= 400;
    }

    /** True when the request carried no body bytes (or the log recorded {@code -}). */
    public boolean hasNoBytes() {
        return bytes <= 0;
    }
}
