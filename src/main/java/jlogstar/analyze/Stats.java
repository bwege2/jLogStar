package jlogstar.analyze;

/** Small numeric helpers: log-gamma and Poisson upper tail in log space. */
public final class Stats {
    private Stats() {}

    public static double lgamma(double x) {
        double r = 0;
        while (x < 7) { r -= Math.log(x); x += 1; }
        double x2 = 1 / (x * x);
        return r + (x - 0.5) * Math.log(x) - x + 0.9189385332046727
                + (1.0 / (12 * x)) * (1 - x2 * (1.0 / 30 - x2 * (1.0 / 105)));
    }

    /** ln P(X >= x) for X ~ Poisson(lambda). */
    public static double poissonLogSf(long x, double lambda) {
        if (x <= 0) return 0;
        if (lambda <= 0) return Double.NEGATIVE_INFINITY;
        if (x <= lambda) return 0;
        double ll = Math.log(lambda);
        double first = x * ll - lambda - lgamma(x + 1.0);
        double sum = 1.0; // relative to first term
        double term = 1.0;
        for (long k = x + 1; k < x + 2000; k++) {
            term *= lambda / k;
            sum += term;
            if (term < 1e-12 * sum) break;
        }
        return first + Math.log(sum);
    }

    public static String fmtDuration(long ms) {
        if (ms < 60_000) return (ms / 1000) + " s";
        if (ms < 3_600_000) return (ms / 60_000) + " min";
        if (ms < 86_400_000) return String.format(java.util.Locale.GERMANY, "%.1f h", ms / 3_600_000.0);
        return String.format(java.util.Locale.GERMANY, "%.1f Tage", ms / 86_400_000.0);
    }

    /** Picks a "nice" bucket size so that span / bucket <= maxBuckets. */
    public static long niceBucket(long span, int maxBuckets) {
        long[] nice = {1_000, 2_000, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000, 600_000, 900_000, 1_800_000,
                3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000, 172_800_000, 604_800_000};
        for (long b : nice) if (span / b < maxBuckets) return b;
        return Math.max(1, span / maxBuckets + 1);
    }
}
