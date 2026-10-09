/*
 * analise.c: o ataque do qui-quadrado de Westfeld e Pfitzmann (1999).
 *
 * Trocar o bit menos significativo por bits aleatórios mistura os pares de
 * valores (0, 1), (2, 3), ..., (254, 255): um 6 vira 7 e vice-versa, mas
 * nunca vira 5. Com dados aleatórios suficientes, cada par fica com as duas
 * contagens iguais. O teste mede o quanto o histograma observado se parece
 * com esse histograma "equalizado".
 */
#include "esteg.h"

#include <math.h>

/* P(a, x), função gama incompleta regularizada inferior, pela série. */
static double gamma_p_series(double a, double x)
{
    double ap = a, sum = 1.0 / a, del = sum;
    for (int n = 1; n < 100000; n++) {
        ap += 1.0;
        del *= x / ap;
        sum += del;
        if (fabs(del) < fabs(sum) * 1e-15)
            break;
    }
    return sum * exp(-x + a * log(x) - lgamma(a));
}

/* Q(a, x) = 1 - P(a, x), por fração contínua (método de Lentz). */
static double gamma_q_fraction(double a, double x)
{
    const double tiny = 1e-300;
    double b = x + 1.0 - a, c = 1.0 / tiny, d = 1.0 / b, h = d;
    for (int i = 1; i < 100000; i++) {
        double an = -i * (i - a);
        b += 2.0;
        d = an * d + b;
        if (fabs(d) < tiny)
            d = tiny;
        c = b + an / c;
        if (fabs(c) < tiny)
            c = tiny;
        d = 1.0 / d;
        double del = d * c;
        h *= del;
        if (fabs(del - 1.0) < 1e-15)
            break;
    }
    return exp(-x + a * log(x) - lgamma(a)) * h;
}

double est_chi2_tail(double x, double degrees)
{
    if (!(degrees > 0))
        return 0.0;
    if (x <= 0)
        return 1.0;
    double a = degrees / 2.0, y = x / 2.0;
    if (y < a + 1.0)
        return 1.0 - gamma_p_series(a, y);
    return gamma_q_fraction(a, y);
}

double est_chi_square(const bmp_image *img, size_t first, size_t count)
{
    double hist[256] = {0};
    size_t total = bmp_channels(img);
    if (first >= total)
        return 0.0;
    if (count > total - first)
        count = total - first;
    for (size_t i = first; i < first + count; i++)
        hist[*bmp_channel(img, i)] += 1.0;

    /* Para cada par, o esperado (se equalizado) é a média das duas contagens. */
    double chi = 0.0;
    int categories = 0;
    for (int k = 0; k < 128; k++) {
        double expected = (hist[2 * k] + hist[2 * k + 1]) / 2.0;
        if (expected <= 0.0)
            continue;
        double diff = hist[2 * k] - expected;
        chi += diff * diff / expected;
        categories++;
    }
    if (categories < 2)
        return 0.0;
    return est_chi2_tail(chi, categories - 1);
}
