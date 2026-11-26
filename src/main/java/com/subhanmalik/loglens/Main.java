package com.subhanmalik.loglens;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * LogLens — access-log analyzer CLI.
 *
 * <p>Usage:
 * <pre>
 *   loglens &lt;file | -&gt; [options]
 *
 *   Options:
 *     --top N            number of entries in each top-N list (default 10)
 *     --status CODES     only include these statuses, e.g. --status 404,500
 *     --method METHODS   only include these methods, e.g. --method GET,POST
 *     --since ISO        only entries at or after this instant
 *                        (e.g. 2026-11-26T00:00:00+05:00)
 *     --until ISO        only entries at or before this instant
 *     --format FMT       common | combined | auto (default auto)
 *     --json             emit JSON instead of the text report
 *     --tolerant         skip malformed lines instead of aborting
 *     --help             print this help
 * </pre>
 *
 * <p>Exit codes: {@code 0} success, {@code 1} usage error,
 * {@code 2} malformed line in strict mode or unreadable input.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out::print, System.err::print));
    }

    /** Runs the CLI; returns the process exit code. Testable without System.exit. */
    static int run(String[] args, java.util.function.Consumer<String> out,
            java.util.function.Consumer<String> err) {
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            err.accept("error: " + e.getMessage() + "\n");
            err.accept(usage());
            return 1;
        }
        if (opts.help) {
            out.accept(usage());
            return 0;
        }

        LogAnalyzer analyzer = new LogAnalyzer(
                opts.since, opts.until, opts.statuses, opts.methods);
        List<LogParseException> errors = new ArrayList<>();
        try {
            if ("-".equals(opts.input)) {
                parseStdin(opts, analyzer, errors);
            } else {
                Path path = Path.of(opts.input);
                if (!Files.isReadable(path)) {
                    err.accept("error: cannot read file: " + opts.input + "\n");
                    return 2;
                }
                errors.addAll(LogParser.parseFile(
                        path, opts.format, opts.tolerant, analyzer::accept));
            }
        } catch (LogParseException e) {
            err.accept("error: " + e.getMessage() + "\n");
            err.accept("  " + e.rawLine() + "\n");
            err.accept("hint: use --tolerant to skip malformed lines\n");
            return 2;
        } catch (IOException e) {
            err.accept("error: failed to read input: " + e.getMessage() + "\n");
            return 2;
        }

        String report = opts.json
                ? Report.json(analyzer, opts.top, errors)
                : Report.text(analyzer, opts.top, errors);
        out.accept(report);
        out.accept("\n");
        if (!errors.isEmpty() && opts.tolerant) {
            err.accept("warning: skipped " + errors.size() + " malformed line(s)\n");
            for (LogParseException e : errors.subList(0, Math.min(5, errors.size()))) {
                err.accept("  line " + e.lineNumber() + ": " + e.rawLine() + "\n");
            }
        }
        return 0;
    }

    private static void parseStdin(Options opts, LogAnalyzer analyzer,
            List<LogParseException> errors) throws IOException, LogParseException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                try {
                    analyzer.accept(LogParser.parseLine(line, lineNumber, opts.format));
                } catch (LogParseException e) {
                    if (!opts.tolerant) {
                        throw e;
                    }
                    errors.add(e);
                }
            }
        }
    }

    static String usage() {
        return """
                LogLens — Apache/Nginx access-log analyzer
                Usage: loglens <file | -> [options]

                  --top N            top-N list size (default 10)
                  --status CODES     include only these statuses, e.g. 404,500
                  --method METHODS   include only these methods, e.g. GET,POST
                  --since ISO        include only entries at/after this instant
                  --until ISO        include only entries at/before this instant
                  --format FMT       common | combined | auto (default auto)
                  --json             emit JSON instead of the text report
                  --tolerant         skip malformed lines instead of aborting
                  --help             print this help
                """;
    }

    /** Parsed command-line options. */
    static final class Options {
        String input;
        int top = 10;
        Set<Integer> statuses;
        Set<String> methods;
        OffsetDateTime since;
        OffsetDateTime until;
        LogParser.Format format = LogParser.Format.AUTO;
        boolean json;
        boolean tolerant;
        boolean help;

        static Options parse(String[] args) {
            Options o = new Options();
            List<String> positional = new ArrayList<>();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "--help", "-h" -> o.help = true;
                    case "--json" -> o.json = true;
                    case "--tolerant" -> o.tolerant = true;
                    case "--top" -> o.top = integerArg(args, ++i, "--top");
                    case "--status" -> o.statuses = statusArg(valueArg(args, ++i, "--status"));
                    case "--method" -> o.methods = methodArg(valueArg(args, ++i, "--method"));
                    case "--since" -> o.since = instantArg(valueArg(args, ++i, "--since"));
                    case "--until" -> o.until = instantArg(valueArg(args, ++i, "--until"));
                    case "--format" -> o.format = formatArg(valueArg(args, ++i, "--format"));
                    default -> {
                        if (arg.startsWith("--")) {
                            throw new IllegalArgumentException("unknown option: " + arg);
                        }
                        positional.add(arg);
                    }
                }
            }
            if (o.help) {
                return o;
            }
            if (positional.size() != 1) {
                throw new IllegalArgumentException(
                        "expected exactly one input file (or - for stdin)");
            }
            o.input = positional.get(0);
            if (o.top < 0) {
                throw new IllegalArgumentException("--top must be >= 0");
            }
            if (o.since != null && o.until != null && o.since.isAfter(o.until)) {
                throw new IllegalArgumentException("--since must not be after --until");
            }
            return o;
        }

        private static String valueArg(String[] args, int i, String flag) {
            if (i >= args.length) {
                throw new IllegalArgumentException(flag + " requires a value");
            }
            return args[i];
        }

        private static int integerArg(String[] args, int i, String flag) {
            try {
                return Integer.parseInt(valueArg(args, i, flag));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(flag + " requires an integer");
            }
        }

        private static Set<Integer> statusArg(String value) {
            Set<Integer> out = new HashSet<>();
            for (String part : value.split(",")) {
                try {
                    int code = Integer.parseInt(part.trim());
                    if (code < 100 || code > 599) {
                        throw new IllegalArgumentException(
                                "invalid status code: " + part.trim());
                    }
                    out.add(code);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("invalid status code: " + part.trim());
                }
            }
            return out;
        }

        private static Set<String> methodArg(String value) {
            Set<String> out = new HashSet<>();
            for (String part : value.split(",")) {
                out.add(part.trim().toUpperCase());
            }
            return out;
        }

        private static OffsetDateTime instantArg(String value) {
            try {
                return OffsetDateTime.parse(value);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException(
                        "invalid ISO-8601 instant: " + value);
            }
        }

        private static LogParser.Format formatArg(String value) {
            return switch (value.toLowerCase()) {
                case "common" -> LogParser.Format.COMMON;
                case "combined" -> LogParser.Format.COMBINED;
                case "auto" -> LogParser.Format.AUTO;
                default -> throw new IllegalArgumentException(
                        "--format must be common, combined or auto");
            };
        }
    }
}
