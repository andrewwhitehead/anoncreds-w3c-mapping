#!/bin/bash

PYTHON=${PYTHON:-python}
OUTPUT=${OUTPUT:-W3COutput}

# Generate all credentials
for i in credentials/*; do
  echo Anoncreds Verifiable Credential: $i
  TARGET="${OUTPUT}/W3C-VC-$(basename $i)"
  $PYTHON credential_to_w3c.py $i > $TARGET
  echo "wrote $TARGET"
done

# Generate all presentations
for i in presentations/*; do
  echo AnonCreds Presentation: $i
  TARGET="${OUTPUT}/W3C-VP-$(basename $i)"
  $PYTHON presentation_to_w3c_vp.py $i > $TARGET
  echo "wrote $TARGET"
done
