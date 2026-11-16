## T1-T4 recall and false alarms

| Label | Malware refs | Benign refs | T1_format recall % | T2_rename recall % | T3_padding recall % | T4_base64 recall % | All-tier recall % (95% CI) | False alarms % (95% CI) | Scan min |
|---|---|---|---|---|---|---|---|---|---|
| old | 8440 | 1949 | 99.4 (527/530) | 97.4 (516/530) | 97.4 (516/530) | 98.3 (521/530) | 98.1 (97.4-98.6) 2080/2120 | 11.50 (9.19-14.30) 69/600 | 92.2 |
| new | 10044 | 2436 | 99.2 (526/530) | 96.4 (511/530) | 96.6 (512/530) | 97.5 (517/530) | 97.5 (96.7-98.0) 2066/2120 | 15.33 (12.67-18.44) 92/600 | 73.7 |

## Difference against old (points; minutes for scan time)

| Label | T1_format | T2_rename | T3_padding | T4_base64 | All-tier recall | False alarms | Scan min |
|---|---|---|---|---|---|---|---|
| new - old | -0.2 | -0.9 | -0.8 | -0.8 | -0.7 | +3.83 | -18.5 |
