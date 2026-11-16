## Learning curve by reference size

| Refs % | Seeds | Malware refs | Benign refs | Recall % mean [min–max] | known_mal_newname % | new_mal_encoded % | new_mal_scripts % | new_mal_shape % | new_mal_stream % | False alarms % mean [min–max] | FA flagged/total (first seed) | Scan min |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 10 | 1 | 861 folders / 514 names | 195 | 86.3 [86.3–86.3] | 84.0 | 89.6 | 86.0 | 84.4 | 87.4 | 17.83 [17.83–17.83] | 107/600 | 21.5 |
| 25 | 1 | 2134 folders / 1286 names | 487 | 91.8 [91.8–91.8] | 85.4 | 91.4 | 96.8 | 88.9 | 97.0 | 13.83 [13.83–13.83] | 83/600 | 22.6 |
| 50 | 1 | 4240 folders / 2571 names | 974 | 94.7 [94.7–94.7] | 89.0 | 97.6 | 97.5 | 93.3 | 97.6 | 12.33 [12.33–12.33] | 74/600 | 25.5 |
| 75 | 1 | 6373 folders / 3856 names | 1462 | 96.3 [96.3–96.3] | 92.8 | 99.1 | 97.5 | 94.7 | 97.8 | 13.33 [13.33–13.33] | 80/600 | 27.1 |
| 100 | 1 | 8440 folders / 5142 names | 1949 | 98.0 [98.0–98.0] | 96.2 | 100.0 | 98.6 | 96.9 | 98.8 | 11.50 [11.50–11.50] | 69/600 | 28.4 |

## Per-seed rows

| Seed | Refs % | Malware recall % (95% CI) | Flagged/expected | Missing reports | False alarms % (95% CI) | FA flagged/total | Scan s |
|---|---|---|---|---|---|---|---|
| 20261114 | 10 | 86.3 (84.7–87.8) | 1593/1846 | 0 | 17.83 (14.98–21.10) | 107/600 | 1290 |
| 20261114 | 25 | 91.8 (90.5–93.0) | 1695/1846 | 0 | 13.83 (11.30–16.83) | 83/600 | 1356 |
| 20261114 | 50 | 94.7 (93.6–95.7) | 1749/1846 | 0 | 12.33 (9.94–15.21) | 74/600 | 1528 |
| 20261114 | 75 | 96.3 (95.3–97.0) | 1777/1846 | 0 | 13.33 (10.85–16.29) | 80/600 | 1624 |
| 20261114 | 100 | 98.0 (97.3–98.6) | 1810/1846 | 0 | 11.50 (9.19–14.30) | 69/600 | 1701 |

Incomplete pairs (excluded):
- seed 20261115 p010: no successful .done for benign, known_mal_newname, new_mal_encoded, new_mal_scripts, new_mal_shape, new_mal_stream
