package com.subhanmalik.loglens;

/**
 * A line that could not be parsed as an access-log entry.
 * Carries the 1-based line number so callers can point at the exact line
 * in the source file, and the raw line for debugging.
 */
public final class LogParseException extends Exception {

    private final int lineNumber;
    private final String rawLine;

    public LogParseException(int lineNumber, String rawLine, String reason) {
        super("line " + lineNumber + ": " + reason);
        this.lineNumber = lineNumber;
        this.rawLine = rawLine;
    }

    public int lineNumber() {
        return lineNumber;
    }

    public String rawLine() {
        return rawLine;
    }
}
