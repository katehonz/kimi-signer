**Validation Policy : Evrotrust validation policy OID=1.3.6.1.4.1.47272.2.9** 

Electronically signed document is validated in accordance with the Evrotrust validation policy OID=1.3.6.1.4.1.47272.2.9.  For further details please read Evrotrust qualified validation practice and policy. 

**Signature SIGNATURE\_DIMITAR-VLADOV-GIGOV INDETERMINATE \-  SIG\_CONSTRAINTS\_FAILURE** 

**Validation Process for Basic Signatures** (Best-signature-time : 2026-04-03 18:58:37  (UTC)) 

Is the result of the 'Format Checking' building block conclusive?   
Is the result of the 'Identification of Signing Certificate' building block conclusive? Is the result of the 'Validation Context Initialization' building block conclusive? Is the result of the 'X.509 Certificate Validation' building block conclusive? Is the result of the 'Cryptographic Verification' building block conclusive? Is the result of the 'Signature Acceptance Validation' building block conclusive? 

Is the result of the Basic Validation Process conclusive?   
Basic Signature Validation process failed with INDETERMINATE/SIG\_CONSTRAINTS\_FAILURE  indication 

**Validation Process for Signatures with Time and Signatures with Long Term Validation Data** (Best-signature-time : 2026-04-03 18:58:37 (UTC)) Is the result of the Basic Validation Process acceptable? 

**Validation Process for Signatures with Archival Data** (Best-signature-time :  2026-04-03 18:58:37 (UTC)) 

Is the result of the LTV validation process acceptable?   
Is long term availability and integrity of validation material present?   
**INDETERMINATE \-**    
**SIG\_CONSTRAINTS\_FAILURE** 

The result of the 'Signature Acceptance Validation'  building block is not conclusive\! 

The result of the Basic validation process is not  conclusive\! 

**INDETERMINATE \-**    
**SIG\_CONSTRAINTS\_FAILURE** 

The result of the Basic validation process is not  acceptable to continue the process\! 

**INDETERMINATE \-**    
**SIG\_CONSTRAINTS\_FAILURE** 

No long term availability and integrity of validation  material is present\! 

**Signature Qualification Indeterminate QESig** 

Is the signature/seal an acceptable AdES digital signature (ETSI EN 319 102-1)? 

Has a trusted list been reached for the certificate chain?   
Is the list of trusted lists acceptable?   
Trusted List : https://ec.europa.eu/tools/lotl/eu-lotl.xml   
Is the trusted list acceptable?   
Trusted List : https://crc.bg/files/\_en/TSL\_BG.xml   
Has been an acceptable trusted list found?   
Is the certificate qualified at (best) signing time?   
Is the certificate type unambiguously identified at (best) signing time? Is the certificate qualified at issuance time? 

Does the private key reside in a QSCD at (best) signing time? 

**Certificate Qualification at certificate issuance time** (2024-03-19  12:32:53 (UTC)) 

Is the certificate related to a trust service at certificate issuance time? Is the certificate related to a CA/QC? 

May a related trust service issue certificates of a suitable type? Is the trust service consistent?   
Trust service name : B-Trust Operational Qualified CA   
Is the certificate related to a trust service with a granted status? Does the trusted certificate match the trust service?   
Is the certificate related to a qualified certificate issuing trust service with valid  status?   
Is the certificate related to a consistent by QC trust service declaration? Is the certificate qualified at issuance time? 

Can the certificate type be issued by a found trust service?   
Is the certificate type unambiguously identified at issuance time? Certificate type is for eSig   
Is the certificate related to a consistent by QSCD trust service declaration? Does the private key reside in a QSCD at issuance time? 

**Certificate Qualification at best signature time** (2026-04-03 18:58:37  (UTC)) 

Is the certificate related to a trust service at best signature time? Is the certificate related to a CA/QC? 

May a related trust service issue certificates of a suitable type? Is the trust service consistent?   
Trust service name : B-Trust Operational Qualified CA   
Is the certificate related to a trust service with a granted status? Does the trusted certificate match the trust service?   
Is the certificate related to a qualified certificate issuing trust service with valid  status? 

The signature/seal is an INDETERMINATE AdES digital  signature\! 

**QC for eSig with QSCD** 

**QC for eSig with QSCD** 

with validation time 2026-04-03T18:58:37Z 1 / 3  
Is the certificate related to a consistent by QC trust service declaration?   
Is the certificate qualified at (best) signing time?   
Can the certificate type be issued by a found trust service?   
Is the certificate type unambiguously identified at (best) signing time?   
Certificate type is for eSig   
Is the certificate related to a consistent by QSCD trust service declaration?   
Does the private key reside in a QSCD at (best) signing time? 

**Basic Building Blocks**   
**SIGNATURE \- SIGNATURE\_DIMITAR-VLADOV-GIGOV** 

**Format Checking : PASSED** Does the signature format correspond to an expected format?   
Is the signature identification not ambiguous?   
Is the signed references identification not ambiguous? 

**Identification of the Signing Certificate : PASSED** Is there an identified candidate for the signing certificate?   
Is the signed attribute: 'cert-digest' of the certificate present?   
Does the certificate digest value match a digest value found in the certificate    
reference(s)?   
Are the issuer distinguished name and the serial number equal? 

**Validation Context Initialization : PASSED** Is the signature policy known? 

**X509 Certificate Validation : PASSED** Can the certificate chain be built till a trust anchor?   
Has a prospective certificate chain valid at validation time been found?   
Validation time : 2026-04-03 18:58   
Is the certificate validation conclusive?   
Is the certificate validation conclusive? 

**Certificate CERTIFICATE\_DIMITAR-VLADOV-GIGOV\_20240319-1232 : PASSED** Is the certificate unique?   
Is a pseudonym used?   
Is certificate not self-signed?   
Is the certificate signature intact?   
Does the certificate's issuer DN match the subject DN of the issuer certificate?   
Does the certificate have an expected key-usage?   
Key usage : \[DIGITAL\_SIGNATURE, NON\_REPUDIATION, KEY\_ENCIPHERMENT\]   
Is the authority info access present?   
Is the certificate's policy tree valid?   
Do certificate's subject names satisfy the imposed name constraints?   
Are all found critical certificate extensions supported?   
Are all found certificate extensions allowed for the certificate?   
Is the revocation info access present?   
Is the revocation data present for the certificate?   
Is an acceptable revocation data present for the certificate?   
Latest acceptable revocation : OCSP\_B-Trust-Qualified-OCSP-Authority\_20260403-1858   
Is the certificate not revoked?   
Is the certificate not on hold?   
Is the revocation freshness check conclusive?   
Id \= OCSP\_B-Trust-Qualified-OCSP-Authority\_20260403-1858   
Are cryptographic constraints met for the signature's certificate chain?   
Signature algorithm RSA with SHA256 with key size 4096 at validation time : 2026-04-03 18:58   
Is the current time in the validity range of the signer's certificate?   
Validation time : 2026-04-03 18:58, certificate validity : 2024-03-19 12:32 \- 2027-03-19 12:32   
Is the certificate of revocation data issuer trusted?   
Certificate Id \= CERTIFICATE\_B-Trust-Qualified-OCSP-Authority\_20220421-1245 

**Certificate Revocation Data Selector : PASSED** Is the revocation acceptance check conclusive?   
Id \= OCSP\_B-Trust-Qualified-OCSP-Authority\_20260403-1858, thisUpdate \= 2026-04-03 18:58,    
production time \= 2026-04-03 18:58   
Is an acceptable revocation data present for the certificate?   
Latest acceptable revocation : OCSP\_B-Trust-Qualified-OCSP-Authority\_20260403-1858 

**Revocation Acceptance Checker : PASSED** Is the revocation status known?   
Does the ResponderId match the OCSP issuer certificate?   
Is it not self issued OCSP Response?   
Is the revocation data consistent?   
Revocation thisUpdate 2026-04-03 18:58 is in the certificate validity range : 2024-03-19 12:32 \-    
2027-03-19 12:32   
Is revocation's signature intact?   
Can the certificate chain be built till a trust anchor?   
2026-04-03T18:58:37Z 

**Revocation Freshness Checker : PASSED** Is the revocation information fresh for the certificate? 

with validation time 2026-04-03T18:58:37Z 2 / 3  
Are cryptographic constraints met for the revocation data signature? Signature algorithm RSA with SHA256 with key size 2048 at validation time : 2026-04-03 18:58 

**Trust Anchor (CERTIFICATE\_B-Trust-Operational-Qualified CA\_20180601-1344)** 

**PASSED** 

**Cryptographic Verification : PASSED** Has the reference data object been found?   
Reference : MESSAGE\_DIGEST   
Is the reference data object intact?   
Reference : MESSAGE\_DIGEST   
Is the signature intact? 

**Signature Acceptance Validation : INDETERMINATE \- SIG\_CONSTRAINTS\_FAILURE** Is the structure of the signature valid?   
Is the signed attribute: 'signing-certificate' present?   
Is the signed attribute: 'signing-certificate' present only once?   
Does the 'Signing Certificate' attribute contain references only to the certificate chain?   
Is the signed qualifying property: 'signing-time' present? 

**Basic Building Blocks**   
**REVOCATION \- OCSP\_B-Trust-Qualified-OCSP-Authority\_20260403-1858** 

The signed qualifying property: 'signing-time' is not  present\! 

**Identification of the Signing Certificate : PASSED** Is there an identified candidate for the signing certificate? 

**X509 Certificate Validation : PASSED** Can the certificate chain be built till a trust anchor?   
Has a prospective certificate chain valid at validation time been found?   
Validation time : 2026-04-03 18:58   
Is the certificate validation conclusive? 

**Trust Anchor (CERTIFICATE\_B-Trust-Qualified-OCSP Authority\_20220421-1245)**   
**PASSED** 

**Cryptographic Verification : PASSED** Is revocation's signature intact? 

**Signature Acceptance Validation : PASSED** Are cryptographic constraints met for the revocation data signature?   
Signature algorithm RSA with SHA256 with key size 2048 at validation time : 2026-04-03 18:58 

**List Of Trusted Lists EU PASSED** 

Is the trusted list fresh?   
Is the trusted list not expired?   
Does the trusted list have the expected version?   
Is the trusted list well signed? 

**Trusted List BG PASSED** 

Is the trusted list fresh?   
Is the trusted list not expired?   
Does the trusted list have the expected version?   
Is the trusted list well signed? 

with validation time 2026-04-03T18:58:37Z 3 / 3