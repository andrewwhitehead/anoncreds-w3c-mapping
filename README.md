# AnonCreds to W3C Format Verifiable Credential and Presentation Converter

This repository contains prototype Python scripts that:

- convert AnonCreds Verifiable Credentials into compliant W3C Format Verifiable Credentials and back, and
- convert AnonCreds Presentations into compliant W3C Format Verifiable Credentials and Verifiable Presentations and back.

These scripts are preliminary work in a possible transition of using the W3C Verifiable Credential Data Model Standard
for AnonCreds verifiable credentials and presentations. As demonstrated by the back and forth nature of the
conversion and the absence of any cryptography library dependencies, nothing is being done to change the AnonCreds signatures
or to alter the semantics of the AnonCreds credentials and presentations. The same AnonCreds code that is currently
used in issuing, holding, proving and verifying AnonCreds continues to be used. The only change is the representation
(arrangement of the JSON) within the credential and presentation.

To run the generator with your own examples:

- Place your AnonCreds credentials JSON in the `credentials` folder, and your AnonCreds presentations in the `presentations` folder.
- Run the bash script `./generateAll`
- Look in the `W3COutput` folder to see all of the converted credentials and presentations.

To run the scripts directly, use:

- `python credential_to_w3c.py <input file> [>output.json]`
- `python presentation_to_w3c_vc.py <input file> [>output.json]`
- `python presentation_to_w3c_vp.py <input file> [>output.json]`

## Notes

- There are two `presentation` converters, one producing a W3C Data Model VC,
  and the other a W3C Data Model VP. We're still debating what is the right way
  to go with what an AnonCreds Presentation should be in W3C format.
- There is no JSON-LD context created for the actual attributes of the AnonCreds
  schema from which the VC is derived, as without changing AnonCreds, there is
not a way for the Issuer to say where the context can be found. Of course, we
could change that and give the issuer a way to do that, or we could
auto-generate a compliant, inline JSON-LD context.
- The converter is not including the `encoded` values of the AnonCreds
  verifiable credential attributes in the W3C formats, putting using instead a
  flag `"encoding": "auto",`, and using converting `raw` to `encoded` data on
  the fly. The encoder matches [Aries RFC 0592 Indy Attachments section on
  Encoding
  Claims](https://github.com/hyperledger/aries-rfcs/tree/main/features/0592-indy-attachments#encoding-claims).
  We think that the code for generating the encoded values should be moved into
  AnonCreds and out of the hands of the Issuer.

Feedback, issues and pull requests welcome!