## Comodo Issues

#### Invalid domains

Comodo issued certs for invalid domains. In specific, `www.sb` which should not have been generated. It has since [been revoked](https://crt.sh/?id=34242572).

#### OCR to validate documents

OCR is a process in which algorithms try to find and understand human/computer writing in digital documents. This process is far from perfect and should only be used as a means of creating faster processes prior to human validation steps. It was found that [OCR algorithms could lead to bogus (and fradulent)](https://bugzilla.mozilla.org/show_bug.cgi?id=1311713) certificates being generated.
