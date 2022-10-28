#!/bin/bash

out=W3COutput

# Generate all credentials
for i in credentials/*; do
  echo Anoncreds Verifiable Credential: $i
  python credential_to_w3c.py $i >${out}/W3C-VC-$(basename $i)
done

# Generate all presentations
for i in presentations/*; do
  echo AnonCreds Presentation: $i
  python presentation_to_w3c_vc.py $i >${out}/W3C-VC-$(basename $i)
  python presentation_to_w3c_vp.py $i >${out}/W3C-VP-$(basename $i)
done
